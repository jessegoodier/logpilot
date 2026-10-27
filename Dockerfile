# registry.access.redhat.com/hi/python:latest is a distroless runtime: no shell and no
# package manager. Install dependencies in the matching builder image, then copy
# the virtualenv and application into the runtime image.
# https://docs.redhat.com/en/documentation/red_hat_hardened_images/
ARG BASE_IMAGE=registry.access.redhat.com/hi/python:latest

FROM ${BASE_IMAGE}-builder AS builder

USER 0
WORKDIR /opt/logpilot-build

COPY pyproject.toml .

RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/python -c "import tomllib, subprocess; deps = tomllib.load(open('pyproject.toml', 'rb'))['project']['dependencies']; subprocess.check_call(['/opt/venv/bin/pip', 'install', '--no-cache-dir', *deps])" \
    && chmod -R a+rX /opt/venv

FROM ${BASE_IMAGE}

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY src/main.py src/log_archiver.py src/index.html ./

EXPOSE 5001

# Exec form: the runtime image has no shell.
CMD ["python3", "/app/main.py"]
