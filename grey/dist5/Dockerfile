# wasm dockerfile credits @ DiceCTF 2021
FROM busybox AS wasmtime

WORKDIR /
RUN wget -O - https://github.com/bytecodealliance/wasmtime/releases/download/v16.0.0/wasmtime-v16.0.0-x86_64-linux.tar.xz \
		| tar -xJ wasmtime-v16.0.0-x86_64-linux/wasmtime

FROM pwn.red/jail@sha256:ee52ad5fd6cfed7fd8ea30b09792a6656045dd015f9bef4edbbfa2c6e672c28c

COPY --from=ubuntu:22.04 / /srv
COPY --from=wasmtime /wasmtime-v16.0.0-x86_64-linux/wasmtime /srv/usr/bin/wasmtime

COPY run.sh /srv/app/run
COPY flag.txt cache.toml pin chall /srv/app/
RUN mkdir /srv/app/cache
RUN chmod +x /srv/app/run

ENV JAIL_MEM 20971520
ENV JAIL_POW 15000

