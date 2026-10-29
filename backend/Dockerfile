FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# git is needed for repo mode (shallow clones)
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Inside this container there is no Docker daemon, so generated tests run in the
# hardened subprocess sandbox. To use per-run containers instead, run the backend
# on the host (recommended) or mount the Docker socket and set SANDBOX_MODE=docker.
ENV SANDBOX_MODE=subprocess

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
