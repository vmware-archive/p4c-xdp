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
<<<<<<< b928c810c7ec65b70a9e48539f2a68a05af2522e
             libboost-iostreams1.62-dev \
=======
             libboost-iostreams1.58-dev \
>>>>>>> Missing dependence
             libgc-dev \
             libgmp-dev \
             libtool \
             pkg-config \
             python \
             python-ipaddr \
             python-scapy \
             python-pip \
             python-setuptools \
             cmake \
             tcpdump \
             git

ENV PROTOBUF_DEPS autoconf \
                  curl \
                  unzip \
		  libprotoc-dev \
		  libprotobuf-c1

RUN apt-get update && apt-get install -y git curl unzip gawk libelf-dev

# curl ca issue
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
RUN apt-get install -y --no-install-recommends xz-utils && \
    cd /tmp && \
    curl -Ssl -o clang+llvm.tar.xz \
        http://releases.llvm.org/3.8.1/clang+llvm-3.8.1-x86_64-linux-gnu-ubuntu-16.04.tar.xz && \
    mkdir -p /usr/local && \
    tar -C /usr/local -xJf ./clang+llvm.tar.xz && \
    mv /usr/local/clang+llvm-3.8.1-x86_64-linux-gnu-ubuntu-16.04 /usr/local/clang+llvm && \
    rm clang+llvm.tar.xz && \
	rm -fr /usr/local/clang+llvm/include/llvm-c && \
	rm -fr /usr/local/clang+llvm/include/clang-c && \
	rm -fr /usr/local/clang+llvm/include/c++ && \
	rm -fr /usr/local/clang+llvm/share && \
	ls -d /usr/local/clang+llvm/lib/* | grep -vE clang$ | xargs rm -r && \
	ls -d /usr/local/clang+llvm/bin/* | grep -vE "clang$|clang-3.8$|llc$" | xargs rm -r
# clang-3.8.1-end

# iproute2-begin
RUN cd /tmp && \
    git clone -b v4.9.0 git://git.kernel.org/pub/scm/linux/kernel/git/shemminger/iproute2.git && \
 	cd /tmp/iproute2 && \
	./configure && \
	make -j `getconf _NPROCESSORS_ONLN` && \
	make install
# iproute2-end
ENV PATH="/usr/local/clang+llvm/bin:$PATH"

# Setup new kernel headers
# P4XDP begin
RUN cd /home/p4c/extensions/p4c-xdp/ && git pull && \
	ln -s /home/p4c/build/p4c-xdp p4c-xdp && \
	cd tests && \
	make

# P4XDP end
