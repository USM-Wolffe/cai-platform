FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PLATFORM_API_HOST=0.0.0.0
ENV PLATFORM_API_PORT=8000

WORKDIR /app

COPY packages/platform-contracts /app/packages/platform-contracts
COPY packages/platform-core /app/packages/platform-core
COPY packages/platform-adapters /app/packages/platform-adapters
COPY packages/platform-backends /app/packages/platform-backends
COPY apps/platform-api /app/apps/platform-api

RUN python -m pip install --no-cache-dir /app/packages/platform-contracts \
    && python -m pip install --no-cache-dir /app/packages/platform-core \
    && python -m pip install --no-cache-dir /app/packages/platform-adapters \
    && python -m pip install --no-cache-dir /app/packages/platform-backends \
    && python -m pip install --no-cache-dir /app/apps/platform-api

EXPOSE 8000

CMD ["platform-api"]
