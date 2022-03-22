#!/bin/bash

# exit when any command fails
set -e

# fetch submodules and update apt
echo "Initializing submodules..."
git submodule update --init --recursive
sudo apt update

SRC_DIR="$(pwd)"

echo "Installing P4C dependencies..."

# Install pip and python
sudo apt install -y python3
sudo apt install -y python3-pip
sudo apt install -y python3-setuptools

# Install the p4 compiler dependencies
sudo apt install -y bison \
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
                    pkg-config

# Install the eBPF dependencies
sudo apt install -y libpcap-dev \
                    libelf-dev \
                    zlib1g-dev \
                    llvm \
                    clang \
                    libprotobuf-dev \
                    protobuf-compiler \
                    iproute2 \
                    tcpdump \
                    iptables

# This only works on Ubuntu 18+
sudo apt install -y libprotoc-dev protobuf-compiler

# install python packages using pip
pip3 install --user wheel
pip3 install --user pyroute2 ipaddr ply==3.8 scapy==2.4.0

echo "Successfully installed P4C dependencies."
