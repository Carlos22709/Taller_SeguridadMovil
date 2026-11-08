# Imagen única: compila la app web (Expo) y la sirve desde FastAPI en el mismo origen.
FROM node:22-slim AS web
WORKDIR /app/mobile-app
COPY mobile-app/package.json mobile-app/package-lock.json ./
RUN npm ci
COPY mobile-app/ ./
RUN npx expo export -p web

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 WEB_DIST_DIR=/app/mobile-app/dist
WORKDIR /app/backend-auth
COPY backend-auth/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend-auth/app ./app
COPY --from=web /app/mobile-app/dist /app/mobile-app/dist
EXPOSE 8000
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips='*'"]
