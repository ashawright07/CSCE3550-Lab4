This program simulates a TCP 3-way handshake.
A file is transfered from client to server. 
The server writes the contents to a file called Results.txt

run: make

Server
run:	./server 1234

Client
run:	./client 1234 <filename>
