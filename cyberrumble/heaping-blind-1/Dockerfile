FROM archlinux:base-devel-20240101.0.204074

RUN pacman -Sy --noconfirm socat

COPY ./heaping-blind-1.c ./flag.txt /

RUN gcc -o /heaping-blind-1 /heaping-blind-1.c

RUN useradd heaping

ENTRYPOINT ["socat", "-v", "TCP-LISTEN:13371,reuseaddr,fork", "EXEC:/heaping-blind-1"]
