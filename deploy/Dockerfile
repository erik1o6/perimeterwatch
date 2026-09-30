# syntax=docker/dockerfile:1
# Build from the repository root:  docker build -f deploy/Dockerfile -t perimeterwatch .
#
# Images are pinned by digest. To update one, look up the new digest and review
# the change like any other dependency bump.

ARG PYTHON_IMAGE=python:3.14-slim@sha256:51dafde81dbdb6ebde285137a295cf18a47ca95234fe388a343719cb97305b3d
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.12.15@sha256:62f8c047d0a0e9ece6b53fc63df902585a67a47a7f318ddec4a37db586edc8e3

FROM ${UV_IMAGE} AS uv

# --- build: install the application and its locked dependencies -----------------
FROM ${PYTHON_IMAGE} AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --extra postgres --no-install-project
COPY src ./src
COPY LICENSE THIRD_PARTY_NOTICES.md README.md ./
RUN uv sync --frozen --no-dev --extra postgres --no-editable

# --- tools: the same installer and the same checksums as on a developer machine ---
FROM build AS tools
RUN PW_DATA_DIR=/tmp/pw /app/.venv/bin/pwatch tools install --all \
 && mkdir -p /opt/pw-tools \
 && cp -a /tmp/pw/tools/. /opt/pw-tools/ \
 && PW_DATA_DIR=/tmp/pw PW_TOOLS_DIR=/opt/pw-tools /app/.venv/bin/pwatch tools verify

# --- runtime --------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runtime
# naabu links against libpcap even for ordinary connect scans.
# The secret scanners use git to read public repositories.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap0.8 ca-certificates git \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --create-home --home-dir /home/pw pw \
 && mkdir -p /data && chown pw:pw /data

COPY --from=build /app/.venv /app/.venv
COPY --from=tools /opt/pw-tools /opt/pw-tools
# The installer keeps its directories private to the user that ran it. The
# service runs as another user, which must be able to read and run the tools.
RUN chmod -R a+rX /opt/pw-tools
# trufflehog is AGPL-3.0 and is shipped unmodified. The notices name its source.
COPY LICENSE THIRD_PARTY_NOTICES.md /app/

ENV PATH=/app/.venv/bin:$PATH \
    PW_ENV=production \
    PW_DATA_DIR=/data \
    PW_TOOLS_DIR=/opt/pw-tools \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER pw
WORKDIR /home/pw
EXPOSE 8000
ENTRYPOINT ["pwatch"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
