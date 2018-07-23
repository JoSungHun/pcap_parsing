all : pcap_parsing

pcap_parsing: main.o
	g++ -g -o pcap_parsing main.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f pcap_parsing
	rm -f *.o

