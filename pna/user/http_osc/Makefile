CC = gcc

CFLAGS = -O3 -w

src = hash_32a.c  http_osc.c murmur3.c  pna_hashmap.c 

target = http_osc

all:
	$(CC) $(CFLAGS) $(src) -o $(target)

clean:
	rm -f $(target)
