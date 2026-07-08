FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gcc \
    && rm -rf /var/lib/apt/lists/*

COPY analyzer/SXF_extract_attacker/requirements.txt /tmp/analyzer-requirements.txt
RUN python -m pip install --upgrade pip \
    && python -m pip install -r /tmp/analyzer-requirements.txt pyyaml

COPY . /app

CMD ["python", "pipeline/run_pipeline.py", "--help"]
