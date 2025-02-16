FROM python:3.11-slim as build

ARG component
ARG poetry_dependency_groups

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    libpq-dev \
    autoconf \
    automake \
    libtool \
    libssl-dev \
    python3-dev

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Build secp256k1
COPY ./crypto-dbpoe /tmp/crypto-dbpoe
WORKDIR /tmp/crypto-dbpoe
RUN ./autogen.sh && \
    ./configure --enable-module-recovery && \
    make && \
    make install

WORKDIR /app
RUN pip install --upgrade pip setuptools poetry cython --no-cache-dir

# Copy dependencies
COPY ./poetry.lock .
COPY ./pyproject.toml .
COPY ./setup_u2sso.py .

# Set up Common
RUN mkdir -p ./common/common/u2sso/
RUN touch ./common/common/__init__.py
RUN touch ./common/common/u2sso/__init__.py
COPY ./common/*.toml common/
COPY ./common/common/u2sso/ common/common/u2sso/

# Install dependencies
RUN python -m venv /app/.venv
RUN . /app/.venv/bin/activate && poetry install --no-root --only ${poetry_dependency_groups}

# Build extension
RUN . /app/.venv/bin/activate && \
    pip install cython && \
    python setup_u2sso.py build_ext --inplace

# Install common package
RUN cd common && /app/.venv/bin/pip install -e .

FROM python:3.11-slim as run

ARG component
ARG COMMIT_HASH
ARG COMMIT_TIMESTAMP
ARG VERSION
ARG install_softhsm

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpq5 \
    libssl3 \
    opensc \
    softhsm2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy built files
COPY --from=build /app/.venv /app/.venv
COPY --from=build /usr/local/lib/libsecp256k1* /usr/local/lib/
COPY --from=build /usr/local/include/secp256k1* /usr/local/include/

ENV COMMIT_HASH=$COMMIT_HASH
ENV COMMIT_TIMESTAMP=$COMMIT_TIMESTAMP
ENV VERSION=$VERSION
ENV COMPONENT=$component
ENV LD_LIBRARY_PATH=/usr/local/lib
ENV PYTHONPATH=/app/common

COPY ./${component}/ ${component}
COPY ./common/ common/
COPY ./${component}/main.py main.py

EXPOSE 8080/tcp

RUN groupadd -r appgroup && useradd -r -g appgroup appuser


ENTRYPOINT ["/app/.venv/bin/uvicorn", "main:app"]
CMD ["--host", "0.0.0.0", "--port", "8080", "--forwarded-allow-ips", "*"]