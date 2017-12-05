#FROM ubuntu:16.04
FROM ubuntu:zesty

WORKDIR /home/
ENV P4C_DEPS automake \
             build-essential \
             bison \
             build-essential \
             flex \
             libfl-dev \
             g++ \
             libboost-dev \
             libboost-iostreams1.62-dev \
             libgc-dev \
             libgmp-dev \
             libtool \
             pkg-config \
             python \
             python-ipaddr \
             python-scapy \
             cmake \
             tcpdump \
             git

ENV PROTOBUF_DEPS autoconf \
                  curl \
                  unzip \
		  libprotoc-dev \
		  libprotobuf-c1

RUN apt-get update && apt-get install -y git curl unzip gawk libelf-dev iproute2 bridge-utils iputils-ping

# P4C and P4C-XDP
COPY . /tmp/p4c-xdp

# P4XDP end
