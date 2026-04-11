FROM node:24-bookworm-slim AS frontend
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.14-slim-bookworm AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SCOPEFORGE_DB=/app/data/scopeforge.sqlite3
WORKDIR /app
COPY backend/ /app/backend/
RUN pip install --no-cache-dir -c backend/requirements.lock ./backend && useradd --uid 10001 --create-home scopeforge && mkdir /app/data && chown scopeforge:scopeforge /app/data
COPY --from=frontend /build/dist /app/frontend/dist
USER scopeforge
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2)"
CMD ["python", "-m", "uvicorn", "scopeforge.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
