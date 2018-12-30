# Makefile to generate dhtest

CC=gcc
#CFLAGS=-Wall -g

dhtest: dhtest.o functions.o 
	$(CC) $(LDFLAGS) dhtest.o functions.o -o dhtest

install: dhtest
	install -d $(DESTDIR)/usr/sbin
	install -D dhtest $(DESTDIR)/usr/sbin/

clean:
	rm -f dhtest functions.o dhtest.o
