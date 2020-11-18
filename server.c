/*
Asha Wright
4/9/20
csce 3530
*/

#include <stdio.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

struct tcp_hdr {                
	unsigned short int src;                
	unsigned short int des;                
	unsigned int seq;                
	unsigned int ack;                
	unsigned short int hdr_flags;                
	unsigned short int rec;            
	unsigned short int cksum;                
	unsigned short int ptr;                
	unsigned int opt; 
	char data[128];             
};

	FILE *fp;
	

unsigned int checksum(struct tcp_hdr tcp_seg);
void printToFile(struct tcp_hdr tcp_seg);

int main(int argc, char *argv[])
{
	FILE *out;
	struct tcp_hdr tcp_seg;
	fp = fopen("server.out", "w");
	out = fopen("results.txt", "ab");
	char buffer[4000];

    	int listen_fd, connfd;
	int tempPort, port;
  	struct sockaddr_in servaddr;
	int addrlen = sizeof(servaddr);

	if(argc < 2)
	{
		printf("ERROR: ./server <port number>\n");
		exit(1);
	}
	
	port = atoi(argv[1]); 

  	/* AF_INET - IPv4 IP , Type of socket, protocol*/
 	listen_fd = socket(AF_INET, SOCK_STREAM, 0);
 
  	bzero(&servaddr, sizeof(servaddr));
 
  	servaddr.sin_family = AF_INET;
  	servaddr.sin_addr.s_addr = htons(INADDR_ANY);
  	servaddr.sin_port = htons(port);
 
  	/* Binds the above details to the socket */
	bind(listen_fd,  (struct sockaddr *) &servaddr, sizeof(servaddr));
	/* Start listening to incoming connections */
	if (listen(listen_fd, 10) == -1)
	{
		printf("listen error\n");
		exit(EXIT_FAILURE);
	}

	/* Accepts an incoming connection */
	connfd = accept(listen_fd, (struct sockaddr*)&servaddr, (socklen_t*)&addrlen);


  	printf("TCP Handshake\n\n");
	fprintf(fp, "TCP Handshake\n\n");

	//recieve SYN
	read(connfd, &tcp_seg, sizeof(tcp_seg));
	if (checksum(tcp_seg) == 0 )
	{
		fprintf(fp, "SYN recieved from client\n");
		printf("SYN recieved from client\n");
		printToFile(tcp_seg);
	}

	//save initial values
	int seq1 = tcp_seg.seq;

	//set SYNACK values
	tempPort = tcp_seg.src;
  	tcp_seg.src = tcp_seg.des;
  	tcp_seg.des = tempPort;

	tcp_seg.seq = 200;
	tcp_seg.ack = seq1 + 1;
	tcp_seg.hdr_flags = 0x12;
	tcp_seg.cksum = 0;
	tcp_seg.cksum = checksum(tcp_seg);
	
	//send SYNACK
	write(connfd, &tcp_seg,sizeof(tcp_seg));

	//recieve ACK with data transfer
	int i = 0;
	
	read(connfd, buffer, sizeof(buffer));
	printf("%d\n", strlen(buffer));
	while(i < strlen(buffer))	
	{

		read(connfd, &tcp_seg, sizeof(tcp_seg));
		if (checksum(tcp_seg) == 0 )
		{
			fprintf(fp, "Data recieved from client\n");
			printf("Data recieved from client\n");
			printToFile(tcp_seg);
		}

		//write tcp_seg.data to file
		fprintf(out, "%s ",tcp_seg.data);


		//set values
		int tempServerSeq = tcp_seg.ack;
		int tempClientSeq = tcp_seg.seq;		

		tcp_seg.seq = tempServerSeq +1;
		tcp_seg.ack = tempClientSeq + 128;
		tcp_seg.hdr_flags = 0x10;
		tcp_seg.cksum = 0;
		tcp_seg.cksum = checksum(tcp_seg);

		//send to client
		write(connfd, &tcp_seg,sizeof(tcp_seg));
		
		i+=128;
	}
	

	//Part 3: Closing 
	printf("\nClosing TCP Connection\n\n");
	fprintf(fp, "\nClosing TCP Connection\n\n");

	//recieve FIN
	read(connfd, &tcp_seg, sizeof(tcp_seg));

	if (checksum(tcp_seg) == 0 )
	{
		fprintf(fp, "FIN recieved from client\n");
		printf("FIN recieved from client\n");
		printToFile(tcp_seg);
	}

	//set ACK values
	tempPort = tcp_seg.src;
  	tcp_seg.src = tcp_seg.des;
  	tcp_seg.des = tempPort;

	int tempServerSeq = tcp_seg.ack;
	int tempClientSeq = tcp_seg.seq;
	
	tcp_seg.seq = tempServerSeq;
	tcp_seg.ack = tempClientSeq+1;
	tcp_seg.hdr_flags = 0x10;
	tcp_seg.cksum = 0;
	tcp_seg.cksum = checksum(tcp_seg);

	//send ACK
	write(connfd, &tcp_seg,sizeof(tcp_seg));

	//set FIN values
	tcp_seg.seq = tempServerSeq;
	tcp_seg.ack = tempClientSeq + 1;
	tcp_seg.hdr_flags = 0x01;
	tcp_seg.cksum = 0;
	tcp_seg.cksum = checksum(tcp_seg);

	//send FIN
	write(connfd, &tcp_seg,sizeof(tcp_seg));

	//receive ACK
	read(connfd, &tcp_seg, sizeof(tcp_seg));
	if (checksum(tcp_seg) == 0 )
	{
		fprintf(fp, "ACK recieved from client\n");
		printf("ACK recieved from client\n");
		printToFile(tcp_seg);
	}


	close(connfd);
	fclose(fp);
	fclose(out);

	return 0;
}

//checksum code given by professor
unsigned int checksum(struct tcp_hdr tcp_seg)
{    
	unsigned short int cksum_arr[12];  
	unsigned int i,sum=0, cksum, wrap;   

	memcpy(cksum_arr, &tcp_seg, 24); //Copying 24 bytes  
 
	for (i=0;i<12;i++)  // Compute sum  
	{      
		sum = sum + cksum_arr[i];  
	}

	wrap = sum >> 16;   // Wrap around once  
	sum = sum & 0x0000FFFF;   
	sum = wrap + sum;  
	wrap = sum >> 16;   // Wrap around once more  
	sum = sum & 0x0000FFFF;  
	cksum = wrap + sum;

	return 0xFFFF^cksum;

	//printf("\nChecksum Value: 0x%04X\n", (0xFFFF^cksum));
}

void printToFile(struct tcp_hdr tcp_seg)
{
	printf("Source Port: %d\n", tcp_seg.src); 
	printf("Destination Port: %d\n", tcp_seg.des);  
	printf("Sequence #: %d\n", tcp_seg.seq);  
	printf("Acknowledgement #: %d\n", tcp_seg.ack);
	printf("Offset: 6 \nHeader Length: 24\n"); 
	printf("Flags: 0x%04X\n", tcp_seg.hdr_flags);
	if(tcp_seg.hdr_flags & 0x02)
  	{
    		printf("SYN = 1\n");
  	} 
	if (tcp_seg.hdr_flags & 0x10) 
  	{
    		printf("ACK = 1\n");
  	} 
	if (tcp_seg.hdr_flags & 0x01)
  	{
    		printf("FIN = 1\n");
  	}
	printf("Receive Window: %d\n", tcp_seg.rec);  
	printf("Checksum: 0x%04X\n", tcp_seg.cksum);  
	printf("Urgent Data Ptr: %d\n", tcp_seg.ptr);  
	printf("Options: %d\n", tcp_seg.opt);
	printf("--------------------------------\n");


	fprintf(fp, "Source Port: %d\n", tcp_seg.src); 
	fprintf(fp, "Destination Port: %d\n", tcp_seg.des);  
	fprintf(fp, "Sequence #: %d\n", tcp_seg.seq);  
	fprintf(fp, "Acknowledgement #: %d\n", tcp_seg.ack);
	fprintf(fp, "Offset: 6 \nHeader Length: 24\n");  
	fprintf(fp, "Flags: 0x%04X\n", tcp_seg.hdr_flags);
	if(tcp_seg.hdr_flags & 0x02)
  	{
    		fprintf(fp,"SYN = 1\n");
  	} 
	if (tcp_seg.hdr_flags & 0x10) 
  	{
    		fprintf(fp,"ACK = 1\n");
  	} if (tcp_seg.hdr_flags & 0x01)
  	{
    		fprintf(fp,"FIN = 1\n");
  	}  
	fprintf(fp, "Receive Window: %d\n", tcp_seg.rec);  
	fprintf(fp, "Checksum: 0x%04X\n", tcp_seg.cksum);  
	fprintf(fp, "Urgent Data Ptr: %d\n", tcp_seg.ptr);  
	fprintf(fp, "Options: %d\n", tcp_seg.opt);
	fprintf(fp, "--------------------------------\n");

}
