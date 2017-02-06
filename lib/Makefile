CC = gcc

all: libbpf.o bpf_load.o

libbpf.o: libbpf.c libbpf.h
	$(CC) -g -c libbpf.c

bpf_load.o: bpf_load.c bpf_load.h
	$(CC) -g -c bpf_load.c

clean:
	@rm -f *.o
