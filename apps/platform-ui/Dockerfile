FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY packages/platform-contracts /app/packages/platform-contracts
COPY packages/platform-core /app/packages/platform-core
COPY packages/platform-adapters /app/packages/platform-adapters
COPY packages/platform-backends /app/packages/platform-backends
COPY apps/cai-orchestrator /app/apps/cai-orchestrator
COPY apps/platform-ui /app/apps/platform-ui

RUN pip install --no-cache-dir \
    /app/packages/platform-contracts \
    /app/packages/platform-core \
    /app/packages/platform-adapters \
    /app/packages/platform-backends \
    "/app/apps/cai-orchestrator[cai]" \
    "/app/apps/platform-ui[cai]"

EXPOSE 8501

CMD ["python", "-m", "streamlit", "run", \
     "apps/platform-ui/src/platform_ui/app.py", \
     "--server.port=8501", \
     "--server.address=0.0.0.0", \
     "--server.baseUrlPath=/ui", \
     "--server.maxUploadSize=2000"]
