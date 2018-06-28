FROM ubuntu:artful

WORKDIR /home/
ENV P4C_DEPS automake \
             build-essential \
             bison \
             build-essential \
             flex \
             libfl-dev \
             g++ \
             libboost-dev \
             libboost-iostreams-dev \
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

RUN apt-get update && apt-get install -y git curl unzip gawk libelf-dev bridge-utils iputils-ping

RUN curl http://curl.haxx.se/ca/cacert.pem | awk '{print > "cert" (1+n) ".pem"} /-----END CERTIFICATE-----/ {n++}' && c_rehash

RUN apt-get install -y --no-install-recommends $P4C_DEPS
RUN apt-get install -y --no-install-recommends $PROTOBUF_DEPS

RUN ldconfig
ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib

# Protocol buf
RUN git clone https://github.com/google/protobuf.git && \
    cd protobuf && \
    git checkout -b p4c v3.0.2 && \
    ./autogen.sh && ./configure && make -j4 && make install && \
    echo PROTOBUF-OK && \
    cd ../

# P4C and P4C-XDP
COPY . /tmp/p4c-xdp

RUN git clone https://github.com/p4lang/p4c.git && \
    cd p4c && \
    git submodule update --init --recursive && \
    git submodule update --recursive && \
# p4xdp download begin
    mkdir extensions && \
    cd extensions && \
#   git clone https://github.com/williamtu/p4c-xdp.git && \
    ln -s /tmp/p4c-xdp p4c-xdp

# p4xdp download end
# build p4c-xdp
RUN cd /home/p4c/ && \
    mkdir -p build && \
    cd build && \
    cmake .. && \
    make -j `getconf _NPROCESSORS_ONLN` && \
    make install && \
    cd ..

# COPY from cilium
# clang-3.8.1-begin
RUN apt-get install -y llvm-4.0 && ln -s /usr/bin/llc-4.0 /usr/bin/llc
RUN apt-get install -y clang-4.0 && ln /usr/bin/clang-4.0 /usr/bin/clang

# iproute2-next
RUN cd /tmp && \
    git clone -b v4.14.0 https://git.kernel.org/pub/scm/linux/kernel/git/dsahern/iproute2-next.git/ && \
	cd /tmp/iproute2-next && git checkout -b v414 && \
	./configure && \
	make -j `getconf _NPROCESSORS_ONLN` && \
	make install
# iproute2-end
ENV PATH="/usr/local/clang+llvm/bin:$PATH"

# Setup new kernel headers
# P4XDP begin
RUN apt-get install -y sudo
RUN cd /home/p4c/extensions/p4c-xdp/ && git pull && \
	ln -s /home/p4c/build/p4c-xdp p4c-xdp && \
	cd tests && \
	make

# P4XDP end
