FROM ubuntu:bionic

WORKDIR /home/
ENV P4C_DEPS bison \
             build-essential \
             cmake \
             git \
             flex \
             libboost-dev \
             libboost-graph-dev \
             libboost-iostreams-dev \
             libfl-dev \
             libgc-dev \
             libgmp-dev \
             pkg-config \
             python-ipaddr \
             python-pip \
             python-setuptools

ENV P4C_EBPF_DEPS libpcap-dev \
             libelf-dev \
             llvm \
             clang \
             libprotobuf-dev \
             protobuf-compiler \
             iproute2 \
             tcpdump

ENV P4C_PIP_PACKAGES pyroute2 \
                     ply==3.8 \
                     scapy==2.4.0

RUN apt-get update
RUN apt-get install -y --no-install-recommends $P4C_DEPS
RUN apt-get install -y --no-install-recommends $P4C_EBPF_DEPS
# in some cases wheel is needed to install pip packages
RUN pip install wheel
RUN pip install $P4C_PIP_PACKAGES

# p4c download begin
RUN git clone https://github.com/p4lang/p4c.git && \
    cd p4c && \
    git submodule update --init --recursive && \
    git submodule update --recursive && \
    mkdir extensions
# p4c download end

# copy xdp into the extension folder
COPY . /home/p4c/extensions/p4c-xdp
RUN ln -s /home/p4c /home/p4c/extensions/p4c-xdp

# build p4c and p4c-xdp
RUN cd /home/p4c/ && \
    mkdir -p build && \
    cd build && \
    cmake .. && \
    make -j `getconf _NPROCESSORS_ONLN` && \
    make install && \
    cd ..

# p4c-xdp setup begin
RUN cd /home/p4c/extensions/p4c-xdp/ && \
    # link the compiler
    ln -sf /home/p4c/build/p4c-xdp p4c-xdp && \
    # add xdp to the ebpf backend target folder
    ln -sf /home/p4c/extensions/p4c-xdp/xdp_target.py /home/p4c/backends/ebpf/targets/xdp_target.py && \
    ln -sf /home/p4c/backends/ebpf/run-ebpf-test.py /home/p4c/extensions/p4c-xdp/run-ebpf-test.py
# p4c-xdp setup end
