# Seguridad Móvil — OAuth 2.0 + PKCE, Almacenamiento Seguro y Step-Up 2FA (TOTP)

Laboratorio de Desarrollo Móvil — Universidad de La Sabana, Sesión 14.

App en **React Native (Expo SDK 58, TypeScript estricto)** + backend **FastAPI** en memoria.
Ninguna librería "caja negra": el TOTP, el HMAC-SHA1, el Base32 y el PKCE están implementados a mano.

```
/mobile-app     App Expo (Android / iOS / Web)
/backend-auth   Servidor de autorización + API protegida (FastAPI)
Dockerfile      Imagen única: compila la app web y la sirve desde el backend (un solo link)
render.yaml     Despliegue en Render (HTTPS)
```

---

## 1. Ejecutar en local (5 minutos)

**Requisitos:** Python 3.12+, Node 20.19+ (probado con Node 24).

### Backend

```bash
cd backend-auth
python -m venv .venv
# Windows: .venv\Scripts\activate   ·   macOS/Linux: source .venv/bin/activate
pip install -r requirements-dev.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers
```

- Documentación interactiva: http://localhost:8000/docs
- QR de enrolamiento 2FA: http://localhost:8000/mfa/qr
- Usuario demo: `estudiante@unisabana.edu.co` / `sabana123` · Semilla TOTP: `JBSWY3DPEHPK3PXP`
- Variables de entorno opcionales: ver [backend-auth/.env.example](backend-auth/.env.example)
  (`cp .env.example .env` y agregar `--env-file .env` al comando).

### App — opción A: Web servida por el backend (la de la sustentación)

```bash
cd mobile-app
npm install
npx expo export -p web      # genera mobile-app/dist
```

Con el backend corriendo, abrir **http://localhost:8000**. El backend sirve la app en el mismo
origen, así que no hace falta CORS y la cookie del refresh token es `SameSite=Strict`.

### App — opción B: Web en modo desarrollo (hot reload)

```bash
cd mobile-app
npx expo start --web        # http://localhost:8081 → usa EXPO_PUBLIC_WEB_API_URL de .env.development
```

### App — opción C: Android / iOS

El custom scheme `unisabana-auth://` necesita un **development build** (Expo Go usa `exp://`):

```bash
cd mobile-app
# IP LAN de tu PC (ipconfig / ifconfig). Emulador Android: http://10.0.2.2:8000
echo EXPO_PUBLIC_API_URL=http://192.168.1.20:8000 > .env.development.local
npx expo run:android        # o: npx eas-cli@latest build --profile development
```

> En Windows, permite a Python en el firewall (red privada) para que el teléfono llegue al puerto 8000.

---

## 2. Publicar con un link HTTPS

El navegador solo expone `crypto.subtle` (SHA-1/SHA-256) en **contextos seguros**: `localhost` o HTTPS.
Para compartir un link hace falta HTTPS.

**Render (gratis, permanente):** subir el repo a GitHub → en Render *New → Blueprint* → elegir el repo.
`render.yaml` construye el `Dockerfile` y genera `JWT_SECRET`. El link queda como
`https://unisabana-seguro.onrender.com`. El plan gratuito se duerme tras 15 min sin uso: abrir el link
1 minuto antes de la demo. Como el estado vive en memoria, cada reinicio cierra las sesiones.

**Túnel temporal desde tu PC (sin cuenta):** con el backend sirviendo la app (opción A):
```bash
cloudflared tunnel --url http://localhost:8000
```

---

## 3. Pruebas automáticas

```bash
cd backend-auth && python -m pytest -q     # 32 pruebas: RFC 6238/7636, PKCE, refresh, step-up, replay
cd mobile-app  && npm test                 # 27 pruebas: RFC 6238/2202/7636, paridad con Python, cola de refresh
cd mobile-app  && npm run typecheck && npx expo lint
```

---

## 4. Guion de la sustentación (5 pruebas de aceptación)

| # | Prueba | Cómo demostrarla en la app | Resultado esperado |
|---|---|---|---|
| 1 | **OAuth + PKCE** | Login → muestra `code_verifier`, `code_challenge` y `state` → *Iniciar sesión con UniSabana*. Se abre el navegador del sistema (en web, una ventana emergente) con el login del servidor → *Autorizar*. | Vuelve a la app con sesión iniciada. En *Inicio*: `access_token` en memoria y `refresh_token` en Keychain/Keystore (en web, cookie HttpOnly). |
| 2 | **Paridad TOTP** | Abrir `/mfa/qr` y escanearlo con Google Authenticator y con la app (*Authenticator → Escanear QR*, o pegar `JBSWY3DPEHPK3PXP`). | Los mismos 6 dígitos al mismo tiempo. |
| 3 | **Modo Avión** | Con la cuenta ya cargada, activar Modo Avión (o en web: DevTools → Network → *Offline*) y esperar a que el contador llegue a 0. | El código cambia sin red. La tarjeta "Cómo se obtiene el código" muestra T, el contador de 64 bits y el truncamiento. |
| 4 | **Step-Up + Bóveda** | *Bóveda → Abrir Bóveda Crítica* → la API responde `403 mfa_required` → aparece el modal 2FA → escribir el código. | Se abre la bóveda con un `elevated_token` (`mfa_verified: true`, 10 min y cuenta regresiva). |
| 5 | **Anti-Replay** | En *Bóveda → Prueba anti-replay → Reenviar el mismo código*. | `409 Conflict · Replay Attack Detected`. |

Extra (Punto 2): *Inicio → Expirar token + 3 peticiones simultáneas*. El registro muestra 3 respuestas
401, las peticiones en cola, **un solo** `POST /auth/refresh` y los reintentos con 200. El contador del
servidor confirma 1 llamada. *Revocar refresh_token y forzar 401* muestra que la app limpia todo y
vuelve al login sola.

---

## 5. Cómo se cumple cada punto

### Punto 1 — OAuth 2.0 con PKCE ([oauth.ts](mobile-app/src/auth/oauth.ts), [pkce.ts](mobile-app/src/crypto/pkce.ts), [main.py](backend-auth/app/main.py))
- `code_verifier`: 64 caracteres del alfabeto *unreserved*. Se generan con `getRandomBytes` y *rejection sampling* para no introducir sesgo de módulo.
- `code_challenge = BASE64URL(SHA256(verifier))` sin relleno. Lo verifican el ejemplo del RFC 7636 (Apéndice B) y los tests.
- Navegador seguro: `WebBrowser.openAuthSessionAsync` (ASWebAuthenticationSession / Custom Tabs). **No hay WebView.**
- `state` aleatorio por solicitud, comparado en tiempo constante. Si no coincide, se aborta antes del canje.
- El backend exige `S256`, `redirect_uri` registrada exacta y un `code` de un solo uso (60 s). Además valida `SHA256(code_verifier) === code_challenge`.
- Cliente público: la app **no tiene `client_secret`**.

### Punto 2 — Almacenamiento seguro y Silent Refresh ([session.ts](mobile-app/src/auth/session.ts), [secureStorage.ts](mobile-app/src/storage/secureStorage.ts), [client.ts](mobile-app/src/api/client.ts))
- `access_token` (5 min) y `elevated_token`: solo en memoria (store de módulo + `useSyncExternalStore`).
- `refresh_token` (30 días):
  - en nativo, `expo-secure-store` con `WHEN_UNLOCKED_THIS_DEVICE_ONLY` (Keychain / Keystore);
  - en web, cookie **HttpOnly + SameSite=Strict + Path=/auth**, que JavaScript nunca ve, porque el navegador no tiene Keychain.
- Cola de promesas ante un 401:
  - una sola renovación; las peticiones nuevas esperan en la cola;
  - al renovar, se reintenta cada una una vez;
  - si el refresh falla, se rechaza la cola, se limpia el almacenamiento y la app vuelve al login.
- Casos borde cubiertos:
  - un 401 que llega tarde con el token viejo se reintenta sin renovar otra vez;
  - un fallo de red no borra la sesión.
- Backend: **rotación** del refresh token y **detección de reuso**. Si alguien presenta un token ya rotado, se revoca toda la familia. Los tokens se guardan hasheados con SHA-256.

### Punto 3 — Authenticator propio ([totp.ts](mobile-app/src/crypto/totp.ts), [hmac.ts](mobile-app/src/crypto/hmac.ts), [base32.ts](mobile-app/src/crypto/base32.ts))
- `expo-crypto` solo trae `digest`, así que **HMAC-SHA1 se construye a mano**: `H((K⊕opad) ‖ H((K⊕ipad) ‖ m))`.
- `T = floor(unix/30)` codificado como entero de 64 bits big-endian. Se divide en parte alta y baja porque los operadores de bits de JS trabajan con 32 bits.
- Truncamiento dinámico: `offset = H[19] & 0x0F`, luego `bin_code % 10^6` con `padStart(6, '0')`.
- Validado con los 6 vectores del RFC 6238. La implementación TS y la de Python coinciden, también con contadores mayores a 2³².
- Ingesta del secreto: QR con `expo-camera` (URI `otpauth://`) o semilla Base32 / URI pegada con validación.
- UI:
  - código monoespaciado grande;
  - barra animada continua de 30 s a 0 que pasa a rojo en los últimos 5 s;
  - el código solo se recalcula al cambiar T, así que no parpadea.
- La semilla se guarda en almacenamiento seguro.

### Punto 4 — Step-Up y Anti-Replay ([main.py](backend-auth/app/main.py), [totp.py](backend-auth/app/totp.py))
- `GET /api/boveda-critica` con un token sin `mfa_verified` responde `403 {error: "mfa_required", step_up_token}`.
- `POST /auth/mfa/verify`:
  - valida el `step_up_token` (JWT `typ=step_up`, 5 min), que no sirve como access token;
  - revisa **primero** la caché anti-replay (`usuario:código`, TTL 90 s) y responde **409** si el código ya está ahí;
  - después valida en las ventanas **C-1, C, C+1**;
  - limita a 5 intentos por `step_up_token`.
- Si todo es correcto devuelve un `elevated_token` con `mfa_verified: true` (10 min).

### Endurecimiento adicional
- `Referrer-Policy: no-referrer`, para que el `?code=` no se filtre.
- `X-Frame-Options: DENY` en el login (anti-clickjacking).
- `Cache-Control: no-store` en las respuestas de tokens.
- JWT con algoritmo fijo HS256 (evita `alg: none`).
- Contraseñas con PBKDF2-SHA256 (200 000 iteraciones).

---

## 6. Endpoints

| Método | Ruta | Descripción |
|---|---|---|
| GET/POST | `/oauth/authorize` | Login en el navegador y redirección con `code` + `state` |
| POST | `/auth/oauth/token` | Canje `code` + `code_verifier` por tokens (form-urlencoded) |
| POST | `/auth/refresh` | Rotación del refresh token (JSON `{refresh_token}` o cookie) |
| POST | `/auth/logout` | Revoca la familia de refresh tokens |
| GET | `/api/perfil` | Recurso protegido normal |
| GET | `/api/boveda-critica` | Recurso crítico (requiere `mfa_verified`) |
| POST | `/auth/mfa/verify` | `{step_up_token, code}` → `elevated_token` · 409 si es replay |
| GET | `/mfa/qr` | QR `otpauth://` para enrolar Google Authenticator (solo demo) |
| GET | `/api/demo/stats` | Contador de llamadas a `/auth/refresh` (para la demo) |
