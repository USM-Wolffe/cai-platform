FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# WeasyPrint system dependencies (GLib, Cairo, Pango)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libglib2.0-0 \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    && rm -rf /var/lib/apt/lists/*

COPY packages/platform-contracts /app/packages/platform-contracts
COPY packages/platform-core /app/packages/platform-core
COPY packages/platform-adapters /app/packages/platform-adapters
COPY packages/platform-backends /app/packages/platform-backends
COPY apps/cai-orchestrator /app/apps/cai-orchestrator
COPY apps/platform-ui /app/apps/platform-ui
COPY logo_egs.png logo_egs.svg /app/

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
