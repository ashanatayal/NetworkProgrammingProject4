#include "hw_addrs.h"

#define IP_PROTOCOL 10
#define MULTICAST_IP "220.255.255.19"
#define MPORT 13854
#define IDENTIFICATION 2779

//globals
int pg,rt,udpsend_socket,pf_socket,udprecv_socket;
char sourcevm[5];
char buffer[MAXLINE];


int make_packet(int argc, char const *argv[])
{
	char listTour[argc+1][MAXLINE],temp[INET_ADDRSTRLEN],temp1[INET_ADDRSTRLEN];
	struct sockaddr_in sasend, sarecv;
	struct hostent *he,*he1;
	int j,k;
	struct sockaddr_in multicastIP;
	char* ptr;
	int len;
	socklen_t salen;

	
	/**********************PAYLOAD*****************/
	he = gethostbyname(sourcevm);
	if (he == NULL) { 
		herror("gethostbyname");
		exit(1);
	}
	bzero(temp,sizeof(temp));
	strcpy(listTour[0],he->h_addr_list[0]); 
	printf("IP0 : %s \n",inet_ntop(he->h_addrtype,listTour[0],temp,INET_ADDRSTRLEN));
	  

	for(j=1;j<argc;j++)
	{
		printf("%s \n",argv[j]);
		he1 = gethostbyname(argv[j]);
		
 		if (he1 == NULL) { 
			herror("gethostbyname");
			exit(1);
		}
		bzero(temp,sizeof(temp));
		strcpy(listTour[j],he1->h_addr_list[0]); 
		
		printf("IP%d : %s \n",j,inet_ntop(he1->h_addrtype,listTour[j],temp,INET_ADDRSTRLEN));
		
	}

	//loading multicast
	multicastIP.sin_addr.s_addr = inet_addr(MULTICAST_IP);
    memcpy(&listTour[argc],(char *)&multicastIP.sin_addr.s_addr,4);
	
	//loading port 
	sprintf(listTour[argc+1], "%d",htons(MPORT)); 
	printf("port: %d \n",ntohs(atoi(listTour[argc+1])));
	
	len = 2 + (argc+1)*4 + 2;  //len,ptr,source Ip,IP address of nodes,multicastIP, multicast port
	
	char* payload_buffer = (char*)malloc(len);
	payload_buffer = buffer + sizeof(struct iphdr);
	payload_buffer[0] = len;
	payload_buffer[1] = 6;  //(2+4) to go beyond source address
	
	ptr = payload_buffer + 2;  //offset to first address 
	
	for(k=0;k<(argc+1);k++)
	{
		strcpy(ptr,listTour[k]);  //copying node address 
		memcpy(temp,ptr,4);
		printf(" payload Buffer is %s \n ", inet_ntop(AF_INET,temp,temp1,INET_ADDRSTRLEN)); 
		ptr = ptr + 4;
	}
	
	strcpy(ptr,listTour[argc+1]);  //copying port number
	
	
	/**********************HEADER*****************/
	struct iphdr *iph = (struct iphdr *)buffer;
	
	
	iph->ihl = sizeof(struct iphdr) / sizeof (uint32_t);
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr);
    iph->ttl = 255;
    iph->protocol = IP_PROTOCOL;
    iph->id = htons(IDENTIFICATION);
    iph->check = 0;
   
	//joining multicast group
	bzero(&sasend,sizeof(sasend));
	sasend.sin_family = AF_INET;
	sasend.sin_port = htons(MPORT);
	sasend.sin_addr.s_addr = multicastIP.sin_addr.s_addr;
	salen = sizeof(struct sockaddr);
	
    memcpy(&sarecv, &sasend, salen);
    Bind(udprecv_socket, (struct sockaddr*)&sarecv, salen);

    Mcast_join(udprecv_socket, (struct sockaddr*)&sasend, salen, NULL, 0);

	return len; 
}


int send_packet(char dest[MAXLINE],int len)
{
	struct hostent *he,*he1;
	char srcIP[INET_ADDRSTRLEN],destIP[INET_ADDRSTRLEN];
	int sendbytes;
	struct sockaddr_in destinationaddr;
	
	printf("Source Node : %s \n",sourcevm);
	printf("Destination Node : %s \n\n",dest);
	
	he = gethostbyname(sourcevm);
		
 	if (he == NULL) { 
		herror("gethostbyname");
		exit(1);
	} 
	
	printf("Source IP : %s \n",inet_ntop(AF_INET,he->h_addr_list[0],srcIP,INET_ADDRSTRLEN));
	
	
	he1 = gethostbyname(dest);
		
 	if (he1 == NULL) { 
		herror("gethostbyname");
		exit(1);
	} 
	
	
	
	printf("Destination IP : %s \n\n",inet_ntop(AF_INET,he1->h_addr_list[0],destIP,INET_ADDRSTRLEN));
	
	struct iphdr *iph = (struct iphdr *)buffer;
	
	//adding source and destination Ip to header
	iph->saddr = inet_addr(srcIP);
	iph->daddr = inet_addr(destIP);
	

	bzero(&destinationaddr,sizeof(destinationaddr));
	destinationaddr.sin_family = AF_INET;
	destinationaddr.sin_addr.s_addr = iph->daddr;

	
	printf("Sending packet on route traversal socket \n");
	
	sendbytes = sendto(rt,buffer,sizeof(struct iphdr) + len,0,(struct sockaddr*)&destinationaddr,sizeof(struct sockaddr));
	if(sendbytes < 0)
	{
		printf("sendto function error %d \n", errno);
	} 
	return 0;
}

int main(int argc, char const *argv[])
{
	
	
	int i,len;
	const int on = 1;
	char packet[MAXLINE];
	char dest[MAXLINE],currentnode[MAXLINE];
	int maxfdp,nready,fdp,rt_data;
    fd_set rset;
	char rtbuffer[MAXLINE];
    struct sockaddr_in rtaddr;
	char    time_buff[MAXLINE];
    time_t ticks;
	struct hostent *he;
	int count = 0;
	int recvlen;
	
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
	
	
	if (setsockopt(udprecv_socket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
	{
		 printf("error while set socket \n");
	}
	

	
	if(argc >= 2){
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
	
	strcpy(dest,argv[1]); //first time destination is first node entered through command line
	
	//creating packet i.e data and header
	len = make_packet(argc,argv);
	
	
	
	//sending packet on rt socket
	send_packet(dest,len);
	}
	
	while(1)
    {
        FD_ZERO(&rset);
        FD_SET(rt, &rset);
        FD_SET(pg, &rset);
		FD_SET(udprecv_socket, &rset);
        fdp = max(rt,pg) ;
		maxfdp = max(fdp,udprecv_socket);
        nready = select(maxfdp, &rset, NULL, NULL, NULL);
        if ((nready = select(maxfdp+1, &rset, NULL, NULL, NULL)) < 0)
        {
            printf(" Select error: %d\n", errno);
            continue;
        }
		
		//if packet is received on route traversal socket
		if (FD_ISSET(rt, &rset))
        {
		
			memset(rtbuffer, 0, sizeof(MAXLINE));
            socklen_t sock_len = sizeof(struct sockaddr);
            rt_data = Recvfrom(rt, rtbuffer , MAXLINE, 0, (struct sockaddr *)&rtaddr, &sock_len);
            if(rt_data < 0)
            {
                printf("error in receiving from unix domain socket\n");
            }
			
			
			struct iphdr *rt_recv_hdr = (struct iphdr*)rtbuffer;
			char* rt_recv_payload = rtbuffer + sizeof(struct iphdr);
			recvlen = rt_recv_payload[0];
		
			printf("received len  : %d \n",recvlen);
			
			printf("Identification Received : %d \n",ntohs(rt_recv_hdr->id));
			
			
			if(ntohs(rt_recv_hdr->id) == IDENTIFICATION)
			{
			
					printf("Received Valid Packet \n");
					
					he = gethostbyaddr(&(rt_recv_hdr->saddr),sizeof(rt_recv_hdr->saddr),AF_INET);
					printf("Source Host name: %s\n", he->h_name);
					
					gethostname(currentnode, sizeof currentnode);

					ticks = time(NULL);
					snprintf(time_buff, sizeof(time_buff), "%.24s\r\n", ctime(&ticks));

					printf("<%s> received source routing packet from %s\n",time_buff,he->h_name);
					count++;
					
					if(count == 1)
					{
						printf("%s node is visited for the first time \n",currentnode);
						 
						char multicast[16];
						char temp[MAXLINE];
						struct sockaddr_in sasend, sarecv;
						socklen_t salen;

						memcpy(&multicast,&rt_recv_payload[recvlen-6],4);

						inet_ntop(AF_INET,multicast,temp,INET_ADDRSTRLEN);

						//joining multicast group
						bzero(&sasend,sizeof(sasend));
						sasend.sin_family = AF_INET;
						sasend.sin_port = htons(MPORT);
						sasend.sin_addr.s_addr = inet_addr(temp);
						salen = sizeof(struct sockaddr);
						
						memcpy(&sarecv, &sasend, salen);
						Bind(udprecv_socket, (struct sockaddr*)&sarecv, salen);

						Mcast_join(udprecv_socket, (struct sockaddr*)&sasend, salen, NULL, 0);
						
						
					}
					else
					{
						printf("%s node is visited for the %d time \n",currentnode,count);
					}
					
			}
			else
			{
					printf("Received Invalid Packet.Ignoring Packet \n");
			}
		}
		
		//if packet is received on ping socket
		/* if (FD_ISSET(pg, &rset))
        {
		} */
		
		//if packet is received on unix domain socket
		/* if (FD_ISSET(udprecv_socket, &rset))
        {
		} */
	}
}