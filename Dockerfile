FROM python:3.11-slim

WORKDIR /app

# Non-root user for OpSec hardening
RUN useradd --create-home --shell /bin/bash appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY scripts/ ./scripts/

RUN mkdir -p /data && chown -R appuser:appuser /data /app
USER appuser

ENV PYTHONUNBUFFERED=1
ENV CANARY_SQLITE_PATH=/data/canary.db

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
