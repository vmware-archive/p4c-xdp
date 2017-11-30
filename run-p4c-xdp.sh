#!/bin/sh

# This program is invoked by make check-xdp to run
# some xdp tests.

folder="$1"
verbose=0
shift

while getopts "bvf" opt; do
    case $opt in
        v)
            verbose=1
            ;;
    esac
    shift
done

file="$1"

if [ $verbose -eq "1" ]; then
    echo $folder/build/p4c-xdp $file
fi
$folder/build/p4c-xdp -o tmp.c $file
