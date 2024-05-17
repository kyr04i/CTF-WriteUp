FROM ubuntu:22.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends wget ca-certificates
RUN mkdir -pm755 /etc/apt/keyrings \
    && wget -O /etc/apt/keyrings/winehq-archive.key https://dl.winehq.org/wine-builds/winehq.key \
    && wget -NP /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/debian/dists/bullseye/winehq-bullseye.sources

RUN dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install -y --no-install-recommends winehq-stable xvfb xauth socat \
    && rm -rf /var/lib/apt/lists/*

COPY wine.reg /tmp/
RUN wine regedit.exe /tmp/wine.reg

COPY challenge /
COPY challenge.exe /
COPY run.sh /run.sh
RUN chmod +x / /run.sh

ENTRYPOINT ["./run.sh"]
