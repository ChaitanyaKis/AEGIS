# AEGIS — container image for Cloud Run.
#
# Two targets. The default is the runtime image; `--target test` adds the dev tooling.
#
#   docker build -t aegis:local .                             # runtime (default)
#   docker run --rm -p 8080:8080 aegis:local                  # serve
#   docker run --rm aegis:local python run_benchmark.py       # 302 governance scenarios
#   docker run --rm aegis:local python run_adversarial_report.py   # 25 adversarial attacks
#
#   docker build --target test -t aegis:test .                # adds pytest and ruff
#   docker run --rm aegis:test                                # the full suite
#
# The runtime image deliberately has no test tooling in it. The benchmark and the
# adversarial matrix need none and run in it directly; the unit suite needs pytest and
# therefore needs the test target. Saying otherwise would be a claim this project does not
# get to make about itself.
#
# The image starts in deterministic mode: no credentials, no network call, no spend, and
# every governance control enforced exactly as it is offline. Calling a real Gemini model
# additionally requires AEGIS_SERVICE_ALLOW_LIVE=true *and* configured credentials.
#
# The enterprise inside is the simulator (claude.md section 14) — synthetic, deterministic,
# and not production infrastructure.

# Pinned to a patch release rather than the floating `3.13-slim`, so a rebuild months from
# now installs the interpreter this image was actually verified against. At the time of
# writing both tags resolve to the same manifest:
#   python:3.13.15-slim = sha256:7ce4b6dfe35e55397b7cda544f8a13f191b7ae28dc5aad71fe664dbc9bc2623f
# Replace the tag with that digest if you need a build that cannot drift at all.
FROM ghcr.io/astral-sh/uv:0.11.32 AS uvbin

FROM python:3.13.15-slim AS base

# uv is pinned by version, so the build resolves nothing: `uv sync --frozen` installs
# exactly what uv.lock records, and two builds a year apart produce the same dependency set.
#
# Copied rather than mounted. `RUN --mount=` is BuildKit-only syntax, and Cloud Build's
# `gcr.io/cloud-builders/docker` step runs the *legacy* builder, which fails on it with
# "the --mount option requires BuildKit". A plain `COPY --from=<stage>` is understood by
# both builders. It costs 64 MB in the final image; see the note at the bottom of this file
# for how to get that back if it ever matters.
COPY --from=uvbin /uv /usr/local/bin/uv

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH=/app \
    PORT=8080

# The unprivileged user is created up front, before the virtualenv exists. A later
# `chown -R /app` would rewrite every file in it, and overlayfs stores that rewrite as a
# full second copy of the environment — 200 MB of duplicate layer for a metadata change.
# Nothing in /app needs to be writable at runtime: the service holds no state, writes no
# file, and reads the environment root-owned and world-readable.
RUN useradd --create-home --uid 1001 aegis

WORKDIR /app

# Dependencies first, from the lockfile alone. This layer is invalidated only by a change to
# pyproject.toml or uv.lock — editing a source file no longer reinstalls anything.
# UV_PYTHON_DOWNLOADS=never keeps uv on the base image's interpreter instead of quietly
# fetching a second one into the image.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --extra gemini --no-install-project

# Then the project itself. --no-editable installs a real copy into the environment rather
# than a link back to the build tree.
#
# `src` deliberately stays. Deleting it here saved 2 MB and silently broke the test target:
# that stage re-runs `uv sync`, hatchling builds `packages = ["src/aegis"]` from a directory
# that is no longer there, and the result is an *empty* wheel installed without an error.
# A build step that fails by producing nothing is worse than 2 MB.
COPY README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --extra gemini --no-editable

# tests/fleet.py is the declared organizational configuration the whole suite asserts
# against, and it is what the service demonstrates. A separate copy written for the
# container could drift from the fleet that is actually tested.
COPY tests ./tests
COPY run_service.py run_benchmark.py run_adversarial_report.py run_live_incident.py ./
COPY claude.md ./

# --- test target: the same image plus the tooling the unit suite needs -------------------
FROM base AS test

# `dev` is an *extra* in pyproject.toml, not a PEP 735 dependency group, so uv's default
# dev handling does not reach it and it has to be named. (`--no-dev` in the base stage is
# therefore belt-and-braces: it would matter only if a dev group were added later.)
RUN uv sync --frozen --extra gemini --extra dev --no-editable

# Two tests read docs/A2A.md and assert the documented policy still matches the code. They
# belong to the suite, so the suite's image needs the document. The runtime image does not
# copy it.
COPY docs ./docs
# /app stays root-owned and read-only to the test user, so the two tools that want to write
# a cache into the working directory are pointed elsewhere: pytest is told not to write one
# at all, and ruff is given a path under the user's own home. Nothing else in the suite
# writes to disk.
ENV PYTEST_ADDOPTS="-p no:cacheprovider"     RUFF_CACHE_DIR=/home/aegis/.ruff_cache
USER aegis
CMD ["python", "-m", "pytest", "-q"]

# --- runtime target: the default, and what Cloud Run gets -------------------------------
FROM base AS runtime

USER aegis
EXPOSE 8080

# Cloud Run ignores this and probes the container itself; it is here for local runs.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('PORT', '8080') + '/health', timeout=4)"

CMD ["python", "run_service.py"]

# --- note on image size ------------------------------------------------------------------
#
# `uv` (64 MB) ships in the final image because a legacy-builder-compatible `COPY` cannot be
# undone in a later layer. To get it back, move the two `uv sync` steps into a dedicated
# builder stage and `COPY --from=builder /app/.venv /app/.venv` into runtime -- also plain
# Dockerfile syntax, but a larger change than getting a deployment unblocked warrants.
