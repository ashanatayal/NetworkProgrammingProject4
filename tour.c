#include "hw_addrs.h"

#define IP_PROTOCOL 1385
#define MULTICAST_IP "239.255.255.180"
#define PORT 13854

//globals
int pg,rt,udpsend_socket,pf_socket,udprecv_socket;

int make_payload(char list[100][16],int arg_num)
{
	int i;
	int ptr_val=0;
	
	char* payload_buffer = (char*)malloc(MAXLINE);
	   
	memset(payload_buffer,0,sizeof(payload_buffer));
	
	for(i=0;i<arg_num;i++)
	{
	
	strcpy(payload_buffer+ptr_val, list[i]);
	ptr_val = strlen(list[i]) + ptr_val;
	}
	printf(" \n Buffer is %s \n ", payload_buffer);
	return 0;
}

int main(int argc, char const *argv[])
{
	
	char sourcevm[5];
	int i,j;
	const int on = 1;
	char listTour[argc][INET_ADDRSTRLEN];
	struct hostent *he,*he1;
	

	
	if(argc < 1)
    {
        printf("error");
    }
	
	
	//creating 4 sockets two IP raw socket, PF_Packet, UDP socket 
	
	//ping socket for receiving ICMP echo reply messages
	pg = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	
	if(pg < 0)
    {
        printf("error in creating ping socket\n");
    }
	
	
	//route traversal socket
	rt= socket(AF_INET, SOCK_RAW, IP_PROTOCOL);
    if(rt < 0)
    {
        printf("error in creating route traversal socket\n");
    }
	
	
	//setting socket option for rt socket to IP_HDRINCL
	if (setsockopt(rt, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
		 printf("error while set socket to IP_HDRINCL\n");
	}


    //pf packet socket for sending echo request
	
	pf_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	
	if(pf_socket < 0)
	{
		printf("error in creating pf packet socket\n");
	}
   
    //UDP Socket for multicast communication
	udpsend_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if(udpsend_socket < 0)
    {
         printf("error in creating udp socket\n");
    }

	udprecv_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if(udprecv_socket < 0)
    {
         printf("error in creating udp socket\n");
    }
	
	
	
	gethostname(sourcevm, sizeof sourcevm);
	printf("Source vm : %s \n",sourcevm);
	//Checking for first node, which cannot be source node
	if(strcmp(argv[1],sourcevm) == 0){
		printf("Cannot Start with Source vm. Enter different node \n");
		exit(1);
	}
	
	//Checking for Consecutive nodes.consecutive nodes cannot be same
	for(i=1;i<argc;i++){
		if(strcmp(argv[i],argv[i-1]) == 0){
			printf("Consecutive Nodes cannot be same. Enter different node \n");
			exit(1);
		}
	}
	
	//creating IP payload 
	
	//creating list
	he = gethostbyname(sourcevm);
	if (he == NULL) { 
		herror("gethostbyname");
		exit(1);
	}
	

	inet_ntop(he->h_addrtype,he->h_addr_list[0],listTour[0],INET_ADDRSTRLEN);
	printf("IP0 : %s \n",listTour[0]);			  

	for(j=1;j<argc;j++)
	{
		printf("%s \n",argv[j]);
		he1 = gethostbyname(argv[j]);
		
 		if (he1 == NULL) { 
			herror("gethostbyname");
			exit(1);
		}

		inet_ntop(he1->h_addrtype,he1->h_addr_list[0],listTour[j],INET_ADDRSTRLEN);
		printf("IP%d : %s \n",j,listTour[j]);
	}
	
	strcpy(listTour[argc],MULTICAST_IP);
	sprintf(listTour[argc+1], "%d", PORT); 
	
   


	
	make_payload(listTour,argc+2);
}