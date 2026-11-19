# syntax=docker/dockerfile:1

# ---- builder: install dependencies into an isolated venv ----
# Base image pinned by digest (tags are mutable); Dependabot bumps it.
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS builder
WORKDIR /app
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY requirements.txt .
# pip/setuptools are build tools: uninstall them so they are not shipped.
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install -r requirements.txt \
    && /opt/venv/bin/python -m pip uninstall -y pip setuptools

# ---- runtime: minimal image, non-root, only the venv + app code ----
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS runtime
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
# Create an unprivileged user to run the app (no shell, fixed uid).
RUN groupadd -r app && useradd -r -g app -u 10001 app
# No package installers in the runtime image (smaller attack surface,
# fewer CVEs: setuptools was flagged by Trivy). Not-installed is a no-op.
RUN python -m pip uninstall -y pip setuptools wheel
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY app ./app
USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status==200 else 1)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
