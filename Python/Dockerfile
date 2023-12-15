FROM python:3.11.4-slim-bookworm

RUN apt-get update \
    && \
    apt-get install -y \
    bash \
    curl \
    make \
    vim \
    && \
    apt clean

WORKDIR /work/

ENTRYPOINT ["bash"]
