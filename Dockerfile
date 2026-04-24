FROM python:3.10-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install --no-cache-dir docker psutil requests flask gunicorn psycopg2-binary

COPY sentinel/ /app/sentinel/
COPY openclaw/ /app/openclaw/

RUN touch /app/sentinel/__init__.py /app/openclaw/__init__.py
RUN mkdir -p /app/audit

EXPOSE 8001
