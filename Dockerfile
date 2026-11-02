# Dayag web UI. Build: docker build -t dayag .   Run: docker run -p 8000:8000 dayag
FROM python:3.13-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip wheel --no-cache-dir --wheel-dir /wheels ".[web]"

FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 10001 dayag
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
USER dayag
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')"
# Inside the container the server must listen on all interfaces; publish the
# port only to localhost (-p 127.0.0.1:8000:8000) unless you add authentication.
CMD ["dayag", "serve", "--host", "0.0.0.0", "--port", "8000"]
