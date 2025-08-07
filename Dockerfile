FROM python:3.13-slim
RUN apt-get update && apt-get install -y netcat-openbsd
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
WORKDIR /code/
COPY pyproject.toml .
COPY uv.lock .
ENV UV_PROJECT_ENVIRONMENT="/usr/local/"
RUN uv sync --all-groups --frozen
COPY src/ src
COPY tests/ tests
COPY flake8.cfg .
CMD ["python", "-u", "/code/src/component.py"]