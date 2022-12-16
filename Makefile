c = ~/Downloads/armv5l/cross-compiler-armv5l_2/bin/armv5l-gcc
CFLAGS = -Wall -Wextra -O2  

door: src/x41.c
	$(c) $< -o $@ $(CFLAGS)
