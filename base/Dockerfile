FROM python:3.12-alpine AS connector-base

ARG UV_SYSTEM_PYTHON=true
RUN pip install uv && uv pip install "tenint==0.9.0"


FROM connector-base AS build
ADD ./ /connector/
RUN uv pip install -r /connector/pyproject.toml


FROM build AS test
WORKDIR /connector/
RUN uv pip install "tenint[testing]" \
 && uv pip install --extra testing -r /connector/pyproject.toml
RUN ruff check
RUN python -m pytest --cov-fail-under=80
RUN uv export --format requirements-txt | uv tool run pip-audit
RUN uv tool run \
    --with "bandit[toml,baseline,sarif]" \
    bandit -c pyproject.toml -r . -ll
RUN tenint marketplace
RUN echo $(date '+Y-%m-%d %H:%M%S') > /tested_on


FROM python:3.12-alpine

RUN addgroup -S connector && adduser connector -S -G connector -h /connector
USER connector:connector
WORKDIR /connector/

COPY --from=connector-base /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages 
COPY --from=build /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages 
COPY --from=build --chown=connector:connector /connector /connector
COPY --from=test --chown=connector:connector /tested_on /tested_on

ENTRYPOINT ["python", "connector.py"]
