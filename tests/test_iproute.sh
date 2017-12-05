#!/bin/bash
set -ex
# test whether the system has sudo and iproute2
ip link add dev tmp123 type dummy
ip link show
ip link del dev tmp123
exit 0
