FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py ./app.py
COPY core ./core
COPY templates ./templates

ENV FAST_WEB_HOST=0.0.0.0 \
    FAST_WEB_PORT=5000 \
    FAST_WEB_DEBUG=0 \
    FAST_DB_PATH=/data/ioc_database.db

EXPOSE 5000

HEALTHCHECK --interval=15s --timeout=5s --retries=5 --start-period=10s \
  CMD python3 -c "import urllib.request as u; u.urlopen('http://127.0.0.1:5000/api/health', timeout=3)" || exit 1

ENTRYPOINT ["python3", "app.py"]
