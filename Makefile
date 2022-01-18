# Makefile to generate dhtest

CC=gcc
#CFLAGS=-Wall -g

dhtest: dhtest.o functions.o chksum.o
	$(CC) $(LDFLAGS) $^ -o dhtest

chksum_test: chksum.o functions_test.o dhcp_err.o
	$(CC) -ggdb -O0 -Wall -Wextra $(LDFLAGS) $^ -o chksum_test

.PHONY: test
test: chksum_test
	./chksum_test

.PHONY: debug
debug: chksum_test
	gdb --args ./chksum_test

clean:
	rm -f dhtest chksum_test *.o
