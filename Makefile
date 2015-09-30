CC = gcc
CXX = g++

CFLAGS = -g -Wall -pthread
CXXFLAGS = -g -Wall -pthread 


http-server: http-server.o
	$(CC) $(CFLAGS) -o http-server http-server.o 

http-server_part4.o: http-server.c
	$(CC) $(CFLAGS) -c http-server.c

.PHONY: clean
clean:
		rm -f *.o http-server
.PHONY: all

