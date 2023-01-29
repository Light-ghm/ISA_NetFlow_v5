make:
	g++ flow.cpp -o flow -lpcap

clean:
	rm -r flow