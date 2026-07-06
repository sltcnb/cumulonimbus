FROM python:3.12-slim

LABEL org.opencontainers.image.title="cumulonimbus" \
      org.opencontainers.image.description="Cloud forensics & IR toolkit"

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir ".[aws]"

# Non-root for least privilege.
RUN useradd -m ir && chown -R ir /app
USER ir

VOLUME ["/data"]
ENTRYPOINT ["cumulonimbus"]
CMD ["--help"]
