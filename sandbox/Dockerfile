# Image used by VOID's execution oracle. Built once, then every test run gets a
# fresh throwaway container from it (no network, read-only, non-root).
#   docker build -t void-sandbox:latest ./sandbox
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt && rm /tmp/requirements.txt

# Run as an unprivileged user by default (docker run also passes --user 65534).
USER 65534:65534
WORKDIR /work
CMD ["python", "-m", "pytest", "-q"]
