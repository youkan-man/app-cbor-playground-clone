FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 CBOR_DATA_DIR=/data PORT=8080
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && groupadd --gid 10001 cbor \
    && useradd --uid 10001 --gid cbor --no-create-home cbor \
    && mkdir /data && chown cbor:cbor /data
COPY --chown=cbor:cbor app.py cbor_codec.py ./
COPY --chown=cbor:cbor static ./static
USER cbor
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=2)"
CMD ["python", "app.py"]
