# Makefile to generate dhtest

CC=gcc
# CFLAGS=-Wall

dhtest: dhtest.o functions.o 
	$(CC) dhtest.o functions.o -o dhtest

clean:
	rm -f dhtest functions.o dhtest.o
