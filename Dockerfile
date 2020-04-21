FROM ubuntu

# USAGE:
# docker build -t dhtest .
# docker run -ti --privileged dhtest dhtest -V -N -i eth0 --timeout 10

ADD . /workspace
WORKDIR /workspace

RUN apt-get update && apt-get install -y make gcc

RUN make && mv dhtest /usr/bin

