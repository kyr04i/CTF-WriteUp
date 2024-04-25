FROM ubuntu:20.04

RUN useradd -m ctf

COPY challenge/* /home/ctf/

RUN chown -R ctf:ctf /home/ctf/

WORKDIR /home/ctf
USER ctf

EXPOSE 9001
CMD ["./run.sh"]
