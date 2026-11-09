# Seguridad Móvil — OAuth 2.0 + PKCE, Almacenamiento Seguro y Step-Up 2FA (TOTP)

Laboratorio de Desarrollo Móvil — Universidad de La Sabana.

App en **React Native (Expo SDK 58, TypeScript estricto)** y backend en **FastAPI** con almacenamiento en memoria.
El TOTP, el HMAC-SHA1, el Base32 y el PKCE están implementados a mano, sin librerías como `otplib` o `speakeasy`.

```
/mobile-app     App Expo (se ejecuta con Expo Go)
/backend-auth   Servidor de autorización + API protegida (FastAPI)
```

---

## Cómo ejecutarlo

**Requisitos:** Python 3.12+, Node 20.19+ y la app **Expo Go** en el celular. El celular y el PC deben estar en la misma red Wi-Fi.

### 1. Backend

```bash
cd backend-auth
python -m venv .venv
.venv\Scripts\activate          # macOS/Linux: source .venv/bin/activate
pip install -r requirements-dev.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 2. Variables de entorno (opcional)

El backend funciona sin configurar nada: todas las variables tienen un valor por defecto. Para cambiarlas:

```bash
cd backend-auth
copy .env.example .env          # macOS/Linux: cp .env.example .env
uvicorn app.main:app --host 0.0.0.0 --port 8000 --env-file .env
```

| Variable | Por defecto | Descripción |
|---|---|---|
| `JWT_SECRET` | aleatorio en cada arranque | Secreto para firmar los JWT |
| `ACCESS_TOKEN_TTL` | `300` | Vida del `access_token` (s) |
| `REFRESH_TOKEN_TTL` | `2592000` | Vida del `refresh_token` (30 días) |
| `ELEVATED_TOKEN_TTL` | `600` | Vida del `elevated_token` (s) |
| `STEP_UP_TOKEN_TTL` | `300` | Vida del `step_up_token` (s) |
| `REPLAY_CACHE_TTL` | `90` | Tiempo que un código TOTP queda bloqueado tras usarse (s) |
| `ALLOWED_REDIRECT_URIS` | `unisabana-auth://callback` | Redirect URIs registradas, separadas por coma |
| `ALLOW_EXPO_GO_REDIRECTS` | `true` | Acepta `exp://<ip>:8081/--/callback` (Expo Go) |
| `DEMO_USER_EMAIL` / `DEMO_USER_PASSWORD` | ver *Datos de prueba* | Usuario demo |
| `TOTP_SECRET` | `JBSWY3DPEHPK3PXP` | Semilla Base32 del usuario demo |

La app no necesita variables: toma la IP del backend del link de Expo. Si el backend corre en otra máquina,
se puede fijar con `EXPO_PUBLIC_API_URL=http://<ip>:8000` antes de `npx expo start`.

### 3. App

En otra terminal, con el backend corriendo:

```bash
cd mobile-app
npm install
npx expo start
```

Escanea el QR de la terminal con Expo Go. No hay que configurar IPs: la app toma la IP del PC del link
`exp://<ip>:8081` y llama al backend en `http://<ip>:8000`.

Si el celular no carga, permite **Node.js** y **Python** en el firewall de Windows (redes privadas).

### Datos de prueba

| | |
|---|---|
| Usuario | `estudiante@unisabana.edu.co` |
| Contraseña | `sabana123` |
| Semilla TOTP | `JBSWY3DPEHPK3PXP` |
| QR para Google Authenticator | `http://<ip-del-pc>:8000/mfa/qr` |

---

## Punto 1 — OAuth 2.0 con PKCE

Archivos: [oauth.ts](mobile-app/src/auth/oauth.ts), [pkce.ts](mobile-app/src/crypto/pkce.ts), [main.py](backend-auth/app/main.py)

- **`code_verifier`:**
  - 64 caracteres del alfabeto *unreserved* (RFC 7636);
  - se generan con `getRandomBytes` y *rejection sampling* para evitar sesgo de módulo.
- **`code_challenge`:**
  - `BASE64URL(SHA256(code_verifier))` sin relleno, con método `S256`;
  - verificado con el ejemplo del RFC 7636 (Apéndice B).
- **Navegador del sistema:**
  - `WebBrowser.openAuthSessionAsync` (ASWebAuthenticationSession en iOS y Custom Tabs en Android). **No se usa WebView.**
  - Retorno por deep link al `redirect_uri` de la app.
- **`state` anti-CSRF:**
  - es aleatorio en cada solicitud y se compara en tiempo constante;
  - si no coincide, el flujo se aborta antes del canje.
- **Backend:**
  - exige `S256` y una `redirect_uri` registrada;
  - el `code` es de un solo uso y dura 60 s;
  - en el canje valida que `SHA256(code_verifier) === code_challenge`.
- **Cliente público:** la app no tiene `client_secret`.

## Punto 2 — Almacenamiento seguro y Silent Refresh

Archivos: [session.ts](mobile-app/src/auth/session.ts), [secureStorage.ts](mobile-app/src/storage/secureStorage.ts), [client.ts](mobile-app/src/api/client.ts)

- **`access_token` (5 min):** vive solo en memoria y nunca se persiste.
- **`refresh_token` (30 días):** se guarda en **`expo-secure-store`** (Keychain en iOS, Keystore en Android) con `WHEN_UNLOCKED_THIS_DEVICE_ONLY`.
- **Silent Refresh Queue**, cuando una petición recibe **401**:
  - se hace **una sola** llamada a `/auth/refresh`;
  - las demás peticiones esperan en una cola de promesas;
  - al obtener el token nuevo, cada petición de la cola se reintenta una vez.
- **Si el refresh falla:**
  - se rechaza la cola y se borra el almacenamiento seguro;
  - la app vuelve sola al login;
  - un fallo de red no cierra la sesión.
- **Backend:**
  - el refresh token **rota** en cada uso;
  - si se presenta uno ya usado (reuso), se revoca toda la familia;
  - los tokens se guardan hasheados con SHA-256.

## Punto 3 — Authenticator propio (TOTP RFC 6238)

Archivos: [totp.ts](mobile-app/src/crypto/totp.ts), [hmac.ts](mobile-app/src/crypto/hmac.ts), [base32.ts](mobile-app/src/crypto/base32.ts)

- **HMAC-SHA1 a mano:** `expo-crypto` solo trae hashes, así que el HMAC se construye como `H((K⊕opad) ‖ H((K⊕ipad) ‖ m))`.
- **Contador:** `T = floor(unix / 30)`, codificado como entero de 64 bits big-endian.
- **Truncamiento dinámico:**
  - `offset = H[19] & 0x0F`;
  - se toman 31 bits desde el offset;
  - el código es `bin_code % 10^6`, completado a 6 dígitos.
- **Validación:** los vectores del RFC 6238 y paridad con la implementación del backend en Python.
- **Ingreso de la semilla:**
  - escaneando el QR `otpauth://` con la cámara (`expo-camera`);
  - o escribiendo la semilla Base32 a mano.
  - La semilla se guarda en SecureStore.
- **Interfaz:**
  - código grande en fuente monoespaciada;
  - barra de 30 s a 0;
  - el código no parpadea al recalcularse.
- **Sin red:** todo el cálculo ocurre en el dispositivo y **funciona en Modo Avión**.

## Punto 4 — Step-Up Authentication y Anti-Replay

Archivos: [main.py](backend-auth/app/main.py), [totp.py](backend-auth/app/totp.py), [VaultScreen.tsx](mobile-app/src/screens/VaultScreen.tsx), [MfaModal.tsx](mobile-app/src/ui/MfaModal.tsx)

- **Acceso sin 2FA:** con un token normal, `GET /api/boveda-critica` responde `403 {"error": "mfa_required", "step_up_token": "..."}`.
- **Al abrir la pantalla Bóveda:**
  - la app atrapa el 403 y muestra el modal 2FA;
  - el modal usa teclado numérico.
- **`POST /auth/mfa/verify`:**
  - valida el `step_up_token`, que es temporal (5 min) y no sirve como access token;
  - **anti-replay:** si el código ya fue usado (caché `usuario:código` con TTL de 90 s), responde **`409 Replay Attack Detected`**;
  - valida el TOTP en las ventanas **C-1, C y C+1** para tolerar desfase de reloj;
  - limita los intentos a 5 por `step_up_token`.
- **Si el código es correcto:**
  - devuelve un **`elevated_token`** con `mfa_verified: true`, válido por 10 min;
  - con ese token la bóveda responde 200.

---

## Endpoints

| Método | Ruta | Descripción |
|---|---|---|
| GET/POST | `/oauth/authorize` | Login en el navegador del sistema y redirección con `code` + `state` |
| POST | `/auth/oauth/token` | Canje de `code` + `code_verifier` por tokens |
| POST | `/auth/refresh` | Rotación del refresh token |
| POST | `/auth/logout` | Revoca el refresh token |
| GET | `/api/perfil` | Recurso protegido normal |
| GET | `/api/boveda-critica` | Recurso crítico; requiere `mfa_verified` |
| POST | `/auth/mfa/verify` | `{step_up_token, code}` → `elevated_token`; 409 si es replay |
| GET | `/mfa/qr` | QR `otpauth://` para enrolar el Authenticator |

## Pruebas automáticas

```bash
cd backend-auth && python -m pytest -q    # 36 pruebas: RFC 6238/7636, PKCE, refresh, step-up, replay
cd mobile-app && npm test                 # 27 pruebas: RFC 6238/2202/7636, paridad con Python, cola de refresh
```
