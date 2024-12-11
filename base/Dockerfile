FROM python:3.12-alpine AS connector-base
RUN pip install uv && uv pip install --system tenint
RUN addgroup -S connector && adduser connector -S -G connector -h /connector


FROM connector-base AS build
ADD --chown=connector:connector ./ /connector/
RUN uv pip install --system -r /connector/pyproject.toml


FROM build AS test
WORKDIR /connector/
RUN uv pip install --system "tenint[testing]" \
 && uv pip install --system --extra testing -r /connector/pyproject.toml
RUN ruff check
RUN python -m pytest
RUN uv export --format requirements-txt | uv tool run pip-audit
RUN uv tool run \
    --with "bandit[toml,baseline,sarif]" \
    bandit -c pyproject.toml -r . -ll
RUN echo $(date '+Y-%m-%d %H:%M%S') > /tested_on


FROM build AS release
WORKDIR /connector/
COPY --from=test --chown=connector:connector /tested_on /tested_on
ENTRYPOINT ["python", "connector.py"]
