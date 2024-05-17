FROM archlinux:base-devel-20240101.0.204074

RUN pacman -Sy --noconfirm socat

COPY ./heaping-blind-0.c ./flag.txt /

RUN gcc -o /heaping-blind-0 /heaping-blind-0.c

RUN useradd heaping

ENTRYPOINT ["socat", "-v", "TCP-LISTEN:13370,reuseaddr,fork", "EXEC:/heaping-blind-0"]
