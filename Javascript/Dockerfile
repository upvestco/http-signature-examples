FROM node:20.4.0-bookworm-slim

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
