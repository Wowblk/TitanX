# Built from the monorepo root: the agent depends on the SDK source at titanx/,
# which is no longer vendored under titanx-agent/. See the titanx-agent service
# in apps/knowflow/deploy/docker-compose.yml for the context.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

# The SDK lives at the repo root. Keeping it on PYTHONPATH (instead of relying on
# the site-packages copy) is what lets the gateway's ``../../ui`` lookup resolve
# to the SDK's UI. Its dependencies (fastapi, uvicorn, …) come with this install.
COPY pyproject.toml README.md /app/_sdk/
COPY titanx/ /app/_sdk/titanx/
COPY ui/ /app/_sdk/ui/
RUN pip install --no-cache-dir /app/_sdk

# The agent itself. --no-deps: its only runtime requirement is titanx, already
# installed above, and its ``titanx @ file:../../..`` path dependency would not
# resolve inside the image.
COPY apps/knowflow/titanx-agent/ /app/
RUN pip install --no-cache-dir --no-deps /app

ENV PYTHONPATH=/app/_sdk

EXPOSE 3000
CMD ["python", "run_gateway.py"]
