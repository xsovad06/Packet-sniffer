CC=g++
CFLAGS=-c -Wall
OBJ = ipk-sniffer.o 
MAIN = ipk-sniffer.cpp

all: ipk-sniffer

ipk-sniffer: $(OBJ)
	$(CC) $(OBJ) -o ipk-sniffer -lpcap

ipk-sniffer.o: $(MAIN)
	$(CC) $(CFLAGS) $(MAIN)

clean:
	rm -rf *o ipk-sniffer
