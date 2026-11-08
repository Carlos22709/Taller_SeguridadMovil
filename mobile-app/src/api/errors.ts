export interface ApiErrorBody {
  error?: string;
  message?: string;
  [key: string]: unknown;
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly body: ApiErrorBody = {},
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

/** La sesión no se pudo renovar: hay que volver a iniciar sesión. */
export class SessionExpiredError extends Error {
  constructor() {
    super('Tu sesión expiró. Inicia sesión de nuevo.');
    this.name = 'SessionExpiredError';
  }
}

export class NetworkError extends Error {
  constructor(cause: unknown) {
    super('No se pudo contactar al servidor. Revisa tu conexión.');
    this.name = 'NetworkError';
    this.cause = cause;
  }
}

export function describeError(error: unknown): string {
  if (error instanceof ApiError || error instanceof SessionExpiredError || error instanceof NetworkError) {
    return error.message;
  }
  if (error instanceof Error) return error.message;
  return 'Ocurrió un error inesperado.';
}
