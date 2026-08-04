ARG BUILD_FROM=ghcr.io/home-assistant/base-python:3.13-alpine3.23-2026.06.1
FROM node:22-alpine AS ui
WORKDIR /src
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM ${BUILD_FROM}
LABEL org.opencontainers.image.title="ONE.OS Edge Connector" \
      org.opencontainers.image.description="Read-only Home Assistant commissioning app" \
      org.opencontainers.image.source="https://github.com/Simon3tiw/one-os-home-assistant-addon"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATABASE_URL=sqlite:////data/commissioning.db STATIC_DIR=/app/static PYTHONPATH=/app/backend ALEMBIC_CONFIG=/app/alembic.ini
WORKDIR /app
COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock
COPY backend/one_os_addon ./backend/one_os_addon
COPY alembic.ini ./
COPY backend/alembic ./backend/alembic
COPY --from=ui /src/dist ./static
COPY rootfs /
RUN chmod +x /etc/services.d/one-os/run
EXPOSE 8099
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8099/health >/dev/null || exit 1
