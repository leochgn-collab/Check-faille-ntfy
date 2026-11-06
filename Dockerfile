FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    STATE_FILE=/data/state.json

RUN useradd -r -u 1000 veilleur && mkdir /data && chown veilleur /data

WORKDIR /app
COPY veilleur_cve.py .

USER veilleur
VOLUME ["/data"]

CMD ["python", "veilleur_cve.py"]
