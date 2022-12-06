c = gcc
CFLAGS = -Wall -Wextra -O2  

door: src/x41.c
	$(c) $< -o $@ $(CFLAGS)
