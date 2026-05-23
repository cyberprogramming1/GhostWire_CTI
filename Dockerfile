FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        gcc \
        libffi-dev \
        libssl-dev \
        fonts-liberation \
        libnss3 \
        libatk1.0-0 \
        libatk-bridge2.0-0 \
        libcups2 \
        libdrm2 \
        libxkbcommon0 \
        libxcomposite1 \
        libxdamage1 \
        libxrandr2 \
        libgbm1 \
        libasound2 \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 1000 ghostwire \
 && useradd --uid 1000 --gid ghostwire \
            --shell /bin/bash \
            --create-home ghostwire

WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip --no-cache-dir \
 && pip install --no-cache-dir -r requirements.txt \
 && python -m playwright install chromium --with-deps

COPY --chown=ghostwire:ghostwire app.py          .
COPY --chown=ghostwire:ghostwire config.py        .
COPY --chown=ghostwire:ghostwire requirements.txt .
COPY --chown=ghostwire:ghostwire backend/         ./backend/
COPY --chown=ghostwire:ghostwire pipelines/       ./pipelines/
COPY --chown=ghostwire:ghostwire frontend/        ./frontend/
COPY --chown=ghostwire:ghostwire assets/          ./assets/
COPY --chown=ghostwire:ghostwire .streamlit/      ./.streamlit/

RUN mkdir -p /app/logs /tmp/ghostwire \
 && chown -R ghostwire:ghostwire /app/logs /tmp/ghostwire

USER ghostwire

EXPOSE 8501

ENTRYPOINT ["streamlit", "run", "app.py", \
            "--server.port=8501", \
            "--server.address=0.0.0.0", \
            "--server.headless=true", \
            "--server.fileWatcherType=none", \
            "--browser.gatherUsageStats=false"]