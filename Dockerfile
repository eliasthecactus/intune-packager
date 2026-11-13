FROM python:3.13-slim

# Static analysis tools: 7-Zip, msitools (msiinfo/msiextract), innoextract, cabextract
RUN apt-get update \
 && apt-get install -y --no-install-recommends 7zip msitools innoextract cabextract ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN useradd --create-home --uid 10001 packager \
 && mkdir -p /data && chown packager:packager /data
USER packager

ENV DATA_DIR=/data \
    PYTHONUNBUFFERED=1
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
