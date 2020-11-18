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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

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
	FILE *dt;
	struct tcp_hdr tcp_seg;
	fp = fopen("client.out", "w");
	srand(time(0));

  	int sockfd, n, tempPort, portnum;
    	struct sockaddr_in servaddr, my_addr;
	int tempClientSeq;
	int tempServerSeq;

	if(argc < 3)
	{
		fprintf(stderr, "To run: %s port filename\n", argv[0]);
		exit(1);
	}

	portnum = atoi(argv[1]);
	char file[128];
	//file = argv[2];
	strcpy(file, argv[2]);
	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if(sockfd <0)
	{
		perror("ERROR opening Socket");
		exit(1);
	}

	bzero((char *) &servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(portnum);
	inet_pton(AF_INET,"129.120.151.94",&(servaddr.sin_addr));


	if(connect(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr)) <0)
	{
		fprintf(stderr,"ERROR, on connecting");
		exit(1);
	}

	printf("TCP Handshake\n\n");
	fprintf(fp, "TCP Handshake\n\n");

	//set initial values
	tcp_seg.src = portnum; 
    	tcp_seg.des = portnum;
    	tcp_seg.seq = 100;		
    	tcp_seg.ack = 0;
    	tcp_seg.hdr_flags = 0x02; 
    	tcp_seg.rec = 0;
    	tcp_seg.cksum = checksum(tcp_seg); 
    	tcp_seg.ptr = 0;
    	tcp_seg.opt = 0;
	
	//keep copy of initial seq
	int intialSeq = tcp_seg.seq;

	//send SYN
	n = write(sockfd, &tcp_seg, sizeof(tcp_seg));
	
	//recieve SYNACK
	n = read(sockfd, &tcp_seg, sizeof(tcp_seg));
	if (checksum(tcp_seg) == 0 )
	{
		fprintf(fp, "SYN-ACK received from server\n");
		printf("SYN-ACK received from server\n");
		printToFile(tcp_seg);
	}

	//Part 2: Sending data
	printf("\nTransfering Data\n\n");
	fprintf(fp, "\nTransfering Data\n\n");

	//read file given by user
	int i = 0, j = 0;
	char c;
	char buffer[4000];
	int index = 0;

	dt = fopen(file,"r"); 	//change this to user given filename	
	while((c = fgetc(dt)) != EOF)
	{
		buffer[index] = c;
		//printf("%c", buffer[index]);
		index++;
	}
	buffer[index] = '\0';
	fclose(dt);
	
	write(sockfd, buffer, strlen(buffer));

	while(i < strlen(buffer)-128)	
	{
		//get 128 bytes (characters)
		for(j = 0; j < 127; j++) 		
		{
			if(i < strlen(buffer))
			{
				tcp_seg.data[j] = buffer[i];
				i++;
			}
		}

		//set ACK values
		tempClientSeq = tcp_seg.ack;
		tempServerSeq = tcp_seg.seq;		

		tcp_seg.seq = tempClientSeq + 1;
		tcp_seg.ack = tempServerSeq + 1;
		tcp_seg.hdr_flags = 0x10; 

		tcp_seg.cksum = 0;
		tcp_seg.cksum = checksum(tcp_seg);

		//send ACK
		n = write(sockfd, &tcp_seg, sizeof(tcp_seg));

		//recieve ACK
		n = read(sockfd, &tcp_seg, sizeof(tcp_seg));
		if (checksum(tcp_seg) == 0 )
		{
			fprintf(fp, "Data Transfer Segment\n");
			printf("Data Transfer Segment\n");
			printToFile(tcp_seg);
		}
	}
	
	//Part 3: Closing 
	printf("\nClosing TCP Connection\n\n");
	fprintf(fp, "\nClosing TCP Connection\n\n");

	//set values for FIN
	tempClientSeq = tcp_seg.ack;
	tempServerSeq = tcp_seg.seq;

    	tcp_seg.seq = tempClientSeq;
    	tcp_seg.ack = tempServerSeq+1;
    	tcp_seg.hdr_flags = 0x01; 
	tcp_seg.cksum = 0;
    	tcp_seg.cksum = checksum(tcp_seg);

	//send FIN
	n = write(sockfd, &tcp_seg, sizeof(tcp_seg));

	//recieve ACK
	n = read(sockfd, &tcp_seg, sizeof(tcp_seg));
	if (checksum(tcp_seg) == 0 )
	{
		fprintf(fp, "ACK received from server\n");
		printf("ACK received from server\n");
		printToFile(tcp_seg);
	}

	//receive FIN
	n = read(sockfd, &tcp_seg, sizeof(tcp_seg));
	fprintf(fp, "Fin received from server\n");
	printf("FIN received from server\n");
	printToFile(tcp_seg);

	//set ACK values
	tempPort = tcp_seg.src;
  	tcp_seg.src = tcp_seg.des;
  	tcp_seg.des = tempPort;

	tempClientSeq = tcp_seg.ack;
	tempServerSeq = tcp_seg.seq;

    	tcp_seg.seq = tempClientSeq;
    	tcp_seg.ack = tempServerSeq+1;
    	tcp_seg.hdr_flags = 0x10;
	tcp_seg.cksum = 0; 
    	tcp_seg.cksum = checksum(tcp_seg);
	
	//send ACK
	n = write(sockfd, &tcp_seg, sizeof(tcp_seg));
	

	close(sockfd);
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
  	} if (tcp_seg.hdr_flags & 0x01)
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
