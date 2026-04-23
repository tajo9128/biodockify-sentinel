FROM python:3.10-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install --no-cache-dir docker psutil requests flask

COPY sentinel/ /app/sentinel/
COPY openclaw/ /app/openclaw/

RUN mkdir -p /app/audit

EXPOSE 8001

CMD ["python", "-m", "openclaw.engine", "--serve"]