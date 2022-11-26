c = gcc
CFLAGS = -Wall -O2 -pthread 

door: src/x41.c
	$(c) $< -o $@ $(CFLAGS)
