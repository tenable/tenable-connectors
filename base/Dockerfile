# Connector Base Stage
# --------------------
# This stage installs the base minimum that is common for every connector.
FROM python:3.12-alpine AS connector-base

ARG UV_SYSTEM_PYTHON=true
RUN pip install uv && uv pip install "tenint==0.9.0"


# Connector Build Stage
# ---------------------
# This stage installs both the connector code and the dependent libraries needed
# to ensure that the connector will run.
FROM connector-base AS build
ADD ./ /connector/
RUN uv pip install -r /connector/pyproject.toml


# Connector Test Stage
# --------------------
# In this stage we will install any required testing libraries and tools and
# run the following suite of security and testing tools:
#
# * ruff check :: Code linting and formatting
# * pytest     :: Unit testing and test coverage
# * pip-audit  :: Ensure none of the libraries installed have any security issues
# * bandit     :: Check the code for any potential low-hanging security code issues
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


# Final Image (publish) Stage
# ---------------------------
# In this stage we will pull the installed libraries and code from the relevent
# stages above and configure the image to use a non-root user.
FROM python:3.12-alpine AS publish

RUN addgroup -S connector && adduser connector -S -G connector -h /connector
USER connector:connector
WORKDIR /connector/

COPY --from=connector-base /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages 
COPY --from=build /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages 
COPY --from=build --chown=connector:connector /connector /connector
COPY --from=test --chown=connector:connector /tested_on /tested_on

ENTRYPOINT ["python", "connector.py"]
