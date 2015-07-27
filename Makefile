rssi:rssi.o
	gcc -g -Wall -o rssi rssi.c -lpcap
clean:
	rm *.o rssi

