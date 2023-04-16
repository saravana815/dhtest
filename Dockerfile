FROM ubuntu

# USAGE:
# docker build -t dhtest .
# on mac
#   docker run -ti --privileged dhtest dhtest -V -N -i eth0 --timeout 10
# on windows 10
#   docker run -ti --net=host --privileged dhtest dhtest -V -N -i eth0 --timeout 10

RUN apt-get update && apt-get install -y make gcc python3-minimal
RUN apt-get install -y vim

ADD . /workspace
WORKDIR /workspace

RUN make && cp dhtest /usr/bin
