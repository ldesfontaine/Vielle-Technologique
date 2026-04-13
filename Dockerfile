FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src
COPY config ./config
COPY web ./web

ENV PYTHONUNBUFFERED=1

RUN useradd -r -s /bin/false appuser
USER appuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:${WEB_PORT:-8094}/health')"

CMD ["python", "-m", "src.main"]
