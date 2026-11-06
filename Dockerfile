FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    DATA_DIR=/data

# tzdata : fuseaux horaires pour les heures calmes
RUN pip install --no-cache-dir tzdata && useradd -r -u 1000 veilleur && mkdir /data && chown veilleur /data

WORKDIR /app
COPY app/ .

USER veilleur
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=60s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=4)" || exit 1

CMD ["python", "main.py"]
