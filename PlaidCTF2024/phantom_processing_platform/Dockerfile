# Instructions:
# docker build -t phantom .
# docker run --rm -it -p 1337:1337 phantom

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y qemu-system-arm && \
    rm -rf /var/lib/apt/lists/*

COPY run_qemu.sh /run_qemu.sh
COPY rootfs.cpio /rootfs.cpio
COPY zImage /zImage

RUN chmod +x /run_qemu.sh

EXPOSE 1337

CMD ["/run_qemu.sh"]

