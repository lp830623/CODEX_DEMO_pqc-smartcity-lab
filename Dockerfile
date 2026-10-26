FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        git \
        libssl-dev \
        ninja-build \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
ENV OQS_INSTALL_PATH=/opt/liboqs \
    LD_LIBRARY_PATH=/opt/liboqs/lib \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . \
    && python -c "import oqs; print('liboqs', oqs.oqs_version())"

ENTRYPOINT ["python", "-m", "pqc_smartcity"]
CMD ["demo", "--messages", "1"]
