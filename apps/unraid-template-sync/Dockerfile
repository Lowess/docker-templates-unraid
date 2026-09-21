FROM python:3.13-alpine

RUN apk add --no-cache ca-certificates git tini \
    && update-ca-certificates

WORKDIR /app
COPY sync_service.py /app/sync_service.py

EXPOSE 9000
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9000/healthz', timeout=3)"

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["python", "-u", "/app/sync_service.py"]
