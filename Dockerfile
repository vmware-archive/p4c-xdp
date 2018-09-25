FROM ubuntu:bionic

WORKDIR /home/
ENV P4C_DEPS bison \
             build-essential \
             cmake \
             git \
             flex \
             g++ \
             libboost-dev \
             libboost-graph-dev \
             libboost-iostreams-dev \
             libfl-dev \
             libgc-dev \
             libgmp-dev \
             pkg-config \
             python-ipaddr \
             python-pip \
             python-setuptools \
             tcpdump

ENV P4C_EBPF_DEPS libpcap-dev \
             libelf-dev \
             llvm \
             llvm-dev \
             clang \
             iproute2 \
             net-tools

ENV P4C_PIP_PACKAGES tenjin \
                     pyroute2 \
                     ply \
                     scapy

ENV PROTOBUF_DEPS autoconf \
                  automake \
                  curl \
                  gawk \
                  unzip \
                  libtool \
                  libprotoc-dev \
                  libprotobuf-c1

RUN apt-get update
RUN apt-get install -y --no-install-recommends $P4C_DEPS
RUN apt-get install -y --no-install-recommends $P4C_EBPF_DEPS
RUN pip install wheel
RUN pip install $P4C_PIP_PACKAGES
RUN apt-get install -y --no-install-recommends $PROTOBUF_DEPS

# Install protobuf
RUN git clone https://github.com/google/protobuf.git && \
    cd protobuf && \
    git checkout -b p4c v3.0.2 && \
    ./autogen.sh && ./configure && make -j4 && make install && \
    echo PROTOBUF-OK && \
    cd ../


# p4c download begin
RUN git clone https://github.com/p4lang/p4c.git && \
    cd p4c && \
    git submodule update --init --recursive && \
    git submodule update --recursive && \
    mkdir extensions
# p4c download end

# copy xdp into the extension folder
COPY . /home/p4c/extensions/p4c-xdp

# build p4c and p4c-xdp
RUN cd /home/p4c/ && \
    mkdir -p build && \
    cd build && \
    cmake .. && \
    make -j `getconf _NPROCESSORS_ONLN` && \
    make install && \
    cd ..

# p4c-xdp setup begin
RUN apt-get install -y sudo
RUN cd /home/p4c/extensions/p4c-xdp/ && \
    # link the compiler
    ln -s /home/p4c/build/p4c-xdp p4c-xdp && \
    # add xdp to the ebpf backend target folder
    ln -s /home/p4c/extensions/p4c-xdp/xdp_target.py /home/p4c/backends/ebpf/targets/xdp_target.py && \
    ln -s /home/p4c/backends/ebpf/run-ebpf-test.py /home/p4c/extensions/p4c-xdp/run-ebpf-test.py
# p4c-xdp setup end
