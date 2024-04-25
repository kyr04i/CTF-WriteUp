FROM ubuntu:24.04@sha256:ff0b5139e774bb0dee9ca8b572b4d69eaec2795deb8dc47c8c829becd67de41e
WORKDIR /app
ENV DEBIAN_FRONTEND="noninteractive"
RUN apt-get update --fix-missing                 && \
    apt-get install -qy --no-install-recommends     \
        socat=1.8.*                              && \
    apt-get clean                                && \
    rm -rf /var/lib/apt/lists/                   && \
                                                    \
    userdel ubuntu                               && \
    useradd -d /home/ctf -m ctf -s /bin/bash

COPY --chown=ctf:ctf   --chmod=500 ./file-checker .
COPY --chown=ctf:ctf   --chmod=400 ./flag.txt .
COPY --chown=root:root --chmod=755 ./ld-2.39.so /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2

EXPOSE 4000
USER ctf
ENV LD_BIND_NOW=1
CMD ["socat", "tcp4-listen:4000,reuseaddr,fork", "exec:/app/file-checker,stderr"]