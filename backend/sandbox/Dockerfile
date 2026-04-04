FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        jq \
        python3 \
        python3-pip \
        ripgrep \
        tcpdump \
        tshark \
        yara \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY backend/sandbox/tools.txt /tools.txt

CMD ["bash"]
