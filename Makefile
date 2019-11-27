OBJ=icmp_test


SOURCE=$(wildcard *.c)

CC=gcc
#CC=aarch64-linux-gnu-gcc

LDFLAGS+=-lpthread

$(OBJ): $(patsubst %.c,%.o,$(SOURCE))
	$(CC) $^ -o $@ $(LDFLAGS) -g

all:$(OBJ)
	


clean:
	rm *.o
	rm ./$(OBJ)

