FROM debian:bookworm-slim
COPY hashed-shellcode /home/ctf/chal
RUN chmod 755 /home/ctf/chal
RUN apt-get update
RUN apt-get update && \
    apt-get -y install socat 

EXPOSE 1337
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork","EXEC:/home/ctf/chal"]