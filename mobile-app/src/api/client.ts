import { ApiError, NetworkError, SessionExpiredError, type ApiErrorBody } from './errors';

/**
 * Cliente HTTP (wrapper de fetch) con "Silent Refresh Queue".
 *
 * Ante un 401:
 *  1. La primera petición que lo detecta dispara UNA sola renovación (POST /auth/refresh).
 *  2. Mientras se renueva, toda petición nueva o fallida se ENCOLA (promesa pendiente).
 *  3. Si la renovación funciona: se actualiza el access_token en memoria, se libera la cola
 *     y cada petición se reintenta una vez con el token nuevo.
 *  4. Si falla (refresh vencido/revocado): se rechaza la cola, se limpia el almacenamiento
 *     seguro y la app vuelve al login (onSessionExpired).
 */
export type ClientEvent =
  | { type: 'request'; method: string; path: string; status: number; retry: boolean }
  | { type: 'queued'; path: string; queueSize: number }
  | { type: 'refresh-start' }
  | { type: 'refresh-success'; released: number }
  | { type: 'refresh-failure'; released: number };

export interface ApiClientOptions {
  baseUrl: string;
  getAccessToken: () => string | null;
  /** Ejecuta POST /auth/refresh y devuelve el nuevo access_token (lanza si falla). */
  refreshAccessToken: () => Promise<string>;
  onSessionExpired: () => void;
}

export interface RequestOptions {
  method?: 'GET' | 'POST';
  body?: unknown;
  /** Token explícito (p. ej. elevated_token). Si responde 401, NO se intenta refresh con él. */
  token?: string;
  /** false para endpoints públicos. */
  auth?: boolean;
}

interface QueueEntry {
  resolve: (token: string) => void;
  reject: (error: unknown) => void;
}

export class ApiClient {
  private isRefreshing = false;
  private queue: QueueEntry[] = [];
  private failedToken: string | null = null;
  private listeners = new Set<(event: ClientEvent) => void>();

  constructor(private readonly options: ApiClientOptions) {}

  onEvent(listener: (event: ClientEvent) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  get<T>(path: string, options: Omit<RequestOptions, 'method' | 'body'> = {}) {
    return this.request<T>(path, { ...options, method: 'GET' });
  }

  post<T>(path: string, body: unknown, options: Omit<RequestOptions, 'method' | 'body'> = {}) {
    return this.request<T>(path, { ...options, method: 'POST', body });
  }

  async request<T>(path: string, options: RequestOptions = {}): Promise<T> {
    const useSessionToken = options.auth !== false && !options.token;

    // Paso 1: si ya hay una renovación en curso, esta petición espera en la cola antes de salir.
    if (useSessionToken && this.isRefreshing) {
      await this.enqueue(path);
    }

    const tokenUsed = options.token ?? (useSessionToken ? this.options.getAccessToken() : null);
    const response = await this.send(path, options, tokenUsed, false);

    if (response.status !== 401 || !useSessionToken) {
      return this.parse<T>(response);
    }

    // Este token ya provocó un refresh fallido (su 401 llegó tarde): la sesión ya está cerrada.
    if (tokenUsed !== null && tokenUsed === this.failedToken) {
      throw new SessionExpiredError();
    }

    // Si otra petición ya renovó mientras esta viajaba con el token viejo, solo se reintenta.
    const current = this.options.getAccessToken();
    const freshToken = current && current !== tokenUsed ? current : await this.refreshOnce(path, tokenUsed);
    return this.parse<T>(await this.send(path, options, freshToken, true));
  }

  /** Garantiza una única llamada a /auth/refresh sin importar cuántas peticiones reciban 401. */
  private async refreshOnce(path: string, expiredToken: string | null): Promise<string> {
    if (this.isRefreshing) return this.enqueue(path);

    this.isRefreshing = true;
    this.emit({ type: 'refresh-start' });
    try {
      const token = await this.options.refreshAccessToken();
      this.emit({ type: 'refresh-success', released: this.queue.length });
      this.flush(null, token);
      return token;
    } catch (error) {
      if (error instanceof NetworkError) {
        // Sin conexión no significa sesión revocada: no se borra nada, solo se informa.
        this.flush(error, null);
        throw error;
      }
      this.emit({ type: 'refresh-failure', released: this.queue.length });
      this.failedToken = expiredToken;
      const expired = new SessionExpiredError();
      this.flush(expired, null);
      this.options.onSessionExpired();
      throw expired;
    } finally {
      this.isRefreshing = false;
    }
  }

  private enqueue(path: string): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      this.queue.push({ resolve, reject });
      this.emit({ type: 'queued', path, queueSize: this.queue.length });
    });
  }

  private flush(error: unknown, token: string | null) {
    const pending = this.queue;
    this.queue = [];
    for (const entry of pending) {
      if (token) entry.resolve(token);
      else entry.reject(error);
    }
  }

  private async send(path: string, options: RequestOptions, token: string | null, retry: boolean) {
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (token) headers.Authorization = `Bearer ${token}`;
    if (options.body !== undefined) headers['Content-Type'] = 'application/json';

    let response: Response;
    try {
      response = await fetch(`${this.options.baseUrl}${path}`, {
        method: options.method ?? 'GET',
        headers,
        body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
        credentials: 'include',
      });
    } catch (cause) {
      throw new NetworkError(cause);
    }
    this.emit({ type: 'request', method: options.method ?? 'GET', path, status: response.status, retry });
    return response;
  }

  private async parse<T>(response: Response): Promise<T> {
    const text = await response.text();
    let data: unknown = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = { message: text };
    }
    if (!response.ok) {
      const body = (data ?? {}) as ApiErrorBody;
      throw new ApiError(
        response.status,
        body.error ?? `http_${response.status}`,
        body.message ?? `Error HTTP ${response.status}`,
        body,
      );
    }
    return data as T;
  }

  private emit(event: ClientEvent) {
    this.listeners.forEach((listener) => listener(event));
  }
}
