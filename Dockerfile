FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 BRANDSENTINEL_ENV=production BRANDSENTINEL_HOST=0.0.0.0 BRANDSENTINEL_PORT=8765
WORKDIR /app
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt
COPY backend/ ./backend/
COPY frontend/ ./frontend/
RUN useradd --system --uid 10001 --create-home brandsentinel && mkdir -p /app/backend/data && chown -R brandsentinel:brandsentinel /app
WORKDIR /app/backend
USER brandsentinel
EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/healthz', timeout=2)"
CMD ["python", "server.py", "serve"]
