FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY extract_attacker.py README.md ./
COPY config ./config
COPY modules ./modules
COPY scripts ./scripts
COPY tools ./tools

RUN mkdir -p data outputs

ENTRYPOINT ["python", "extract_attacker.py"]
CMD ["--help"]
