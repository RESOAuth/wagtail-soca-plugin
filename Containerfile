FROM docker.io/library/python:3.12-slim@sha256:2b4f19dae3a777dfc3b76730bda1e82e1f66ab2a2686fa93ca78edbfb4f04ffe

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    RUFF_CACHE_DIR=/tmp/ruff \
    DJANGO_SETTINGS_MODULE=tests.settings
WORKDIR /app
COPY requirements-test.txt /app/requirements-test.txt
RUN pip install --no-cache-dir -r requirements-test.txt
ARG WAGTAIL_VERSION=7.4
RUN if [ "$WAGTAIL_VERSION" != "7.4" ]; then \
        pip install --no-cache-dir "wagtail~=$WAGTAIL_VERSION.0"; \
    fi
COPY . /app
RUN python -m build --no-isolation \
    && pip install --no-cache-dir --no-deps dist/*.whl \
    && python tests/verify_distribution.py dist \
    && pip check \
    && useradd --create-home --uid 10001 tester
COPY tests /suite/tests
USER tester
CMD ["sh", "/suite/tests/container-test.sh"]
