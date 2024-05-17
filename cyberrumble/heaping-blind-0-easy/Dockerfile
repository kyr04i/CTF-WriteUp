FROM archlinux:base-devel-20240101.0.204074

RUN pacman -Sy --noconfirm socat

COPY ./heaping-blind-0-easy.c ./flag.txt /

RUN gcc -o /heaping-blind-0-easy /heaping-blind-0-easy.c

RUN useradd heaping

ENTRYPOINT ["socat", "-v", "TCP-LISTEN:13360,reuseaddr,fork", "EXEC:/heaping-blind-0-easy"]
