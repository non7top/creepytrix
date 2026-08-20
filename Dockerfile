# Disposable, non-root image for the Bitrix pentest tool.
# uid/gid are passed in to match the host user so bind-mounted writes
# (logs, JSON output) don't land root-owned on the host.
FROM python:3.12-slim

ARG UID=1000
ARG GID=1000

# build-essential covers the few deps without a prebuilt wheel; the image is
# disposable so the extra layer is acceptable for reliable builds.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

# Non-root user matching the host uid/gid (group/user may already exist).
RUN groupadd -g ${GID} app 2>/dev/null || true \
    && useradd -m -u ${UID} -g ${GID} -s /bin/bash app 2>/dev/null || true

WORKDIR /app

# Install deps first for layer caching; a BuildKit cache mount keeps the pip
# download cache across rebuilds without a root-owned named volume.
COPY requirements.txt requirements-dev.txt ./
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -r requirements.txt -r requirements-dev.txt

USER app
ENTRYPOINT ["python", "creepytrix.py"]
