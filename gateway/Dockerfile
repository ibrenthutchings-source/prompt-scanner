FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY app ./app

RUN pip install --no-cache-dir . && pip install --no-cache-dir asyncpg

# SQLite fallback for plain `docker run` without a mounted volume or an
# external database — set SCANNER_DATABASE_URL to override (e.g. Postgres).
# No VOLUME directive: Railway's builder rejects it ("use Railway Volumes"
# instead), and Compose/plain Docker work fine without declaring one here.
ENV SCANNER_DATABASE_URL=sqlite+aiosqlite:////data/scanner.db

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
