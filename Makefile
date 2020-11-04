all : airodump

airodump: main.o
	g++ -g -o airodump main.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f airodump
	rm -f *.o

