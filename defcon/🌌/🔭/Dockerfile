FROM mojalaxy/mojo-24.2.0-c2427bc5-release

RUN chmod -R a+rwX /root
ENV MOJO_PYTHON_LIBRARY=/opt/conda/lib

WORKDIR /opt
ADD * e /opt/
ADD */*.py /opt/src/

RUN head -c 60 /dev/urandom > /secret.key
RUN adduser --no-create-home --disabled-password --gecos "" user
USER user

CMD ["/opt/e"]
