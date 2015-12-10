#include "hw_addrs.h"

#define IP_PROTOCOL 10
#define MULTICAST_IP "239.126.255.180"
#define MPORT 13854
#define IDENTIFICATION 222
#define ARP_PATH "ashana"
#define ETH_HDRLEN 14  // Ethernet header length
#define IP4_HDRLEN 20  // IPv4 header length
#define ICMP_HDRLEN 8  // ICMP header length for echo request, excludes data
#define DATALEN 56
#define ETH_PAYLOAD_LEN IP4_HDRLEN + ICMP_HDRLEN + DATALEN
#define ETH_PACKET_LEN ETH_HDRLEN + ETH_PAYLOAD_LEN

//globals
int pg,rt,udpsend_socket,pf_socket,udprecv_socket;
char sourcevm[5];
int len;
struct hwaddr HWaddr;
char previousnode[MAXLINE];
char currentnode[MAXLINE];
pid_t   pid; 
int tourendflag;
int pingendflag;
int nsent;   
char ping_list[10][INET_ADDRSTRLEN];  //ping list to check wether previous node has been already processed 


int send_packet(char sourcevm[MAXLINE],char dest[MAXLINE],char packet[MAXLINE])
{
	struct hostent *he,*he1;
	char srcIP[INET_ADDRSTRLEN],destIP[INET_ADDRSTRLEN];
	int sendbytes;
	struct sockaddr_in destinationaddr;
	
	char* payload_buffer = (char*)malloc(len);
	payload_buffer = packet + sizeof(struct iphdr);

	payload_buffer[1] = payload_buffer[1] + 4;  //(2+4) to go beyond source address
	
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
	
	struct iphdr *iph = (struct iphdr *)packet;
	
	//adding source and destination Ip to header
	iph->saddr = inet_addr(srcIP);
	iph->daddr = inet_addr(destIP);
	

	bzero(&destinationaddr,sizeof(destinationaddr));
	destinationaddr.sin_family = AF_INET;
	destinationaddr.sin_addr.s_addr = iph->daddr;

	
	printf("Sending packet on route traversal socket to next node in tour %s\n\n",dest);
	
	
		sendbytes = sendto(rt,packet,sizeof(struct iphdr) + payload_buffer[0],0,(struct sockaddr*)&destinationaddr,sizeof(struct sockaddr));
		if(sendbytes < 0)
		{
			printf("sendto function error %d \n", errno);
		} 
		
		printf("*********************************************************\n\n");
	
	
	return 0;
}


void make_packet(int argc, char const *argv[],char *dest)
{
	char listTour[argc+1][MAXLINE],temp[INET_ADDRSTRLEN],temp1[INET_ADDRSTRLEN];
	struct sockaddr_in sasend, sarecv;
	struct hostent *he,*he1;
	int j,k;
	struct sockaddr_in multicastIP;
	char* ptr;
	
	socklen_t salen;
	char buffer[MAXLINE];
	
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
    bind(udprecv_socket, (struct sockaddr*)&sarecv, salen);

    mcast_join(udprecv_socket, (struct sockaddr*)&sasend, salen, NULL, 0);

	//sending packet on rt socket
	send_packet(sourcevm,dest,buffer); 
}




int areq (struct sockaddr *IPaddr, socklen_t sockaddrlen, struct hwaddr *HWaddr)
{
    int unixdomain_socket;
    struct sockaddr_un arp_address;
    int nbytes_send,nbytes_rcv;
    char IPaddress[INET_ADDRSTRLEN];
    struct sockaddr_in *IP_in_addr;
    char eth_buf[MAXLINE];
    char* ptr;
    int i;
    int j;
	
    IP_in_addr = (struct sockaddr_in *)IPaddr;
	
	inet_ntop(AF_INET, &IP_in_addr->sin_addr, IPaddress, INET_ADDRSTRLEN);
   // printf("\n The IP address to be resolved in AREQ is %s \n",inet_ntop(AF_INET, &IP_in_addr->sin_addr, IPaddress, INET_ADDRSTRLEN));
    
    
    unixdomain_socket= socket(AF_LOCAL, SOCK_STREAM, 0);
    
    if(unixdomain_socket < 0)
    {
        printf("\n Error in creation of Unix socket in areq \n ");
    }
    
    //unlink(ARP_PATH);
    bzero(&arp_address, sizeof(arp_address));
    arp_address.sun_family = AF_LOCAL;
    strcpy(arp_address.sun_path, ARP_PATH);
    
    
    
    if (connect(unixdomain_socket, (struct sockaddr*)&arp_address, sizeof(arp_address)) < 0)
    {
        printf("\n Error in connecting to unix socket in areq \n");
    }
    
    
    if(nbytes_send = write(unixdomain_socket, IPaddress, INET_ADDRSTRLEN)<0)
    {
        
        printf(" Error in writing to the connection socket \n");
        
    }

    if (nbytes_rcv = read(unixdomain_socket, eth_buf, 6)<0);
    {
        //printf("Read Error on the connection socket \n");
    }
    
    //printf(" %d bytes received from socket \n",nbytes_rcv);
    
    
  printf("Destination MAC Address = ");
    ptr = eth_buf;

    i = 6;
  
	for(j=0;j<6;j++){
	  
	   HWaddr->sll_addr[j] = eth_buf[j] & 0xff;
	 }
         
   do {
        
        printf("%.2x%s", *ptr++ & 0xff, (i == 1) ? " " : ":");
        
    } while (--i > 0); 
    
	printf("\n");
    
    return 0;
    
}

void tv_sub (struct timeval *out, struct timeval *in)
 {
     if ((out->tv_usec -= in->tv_usec) < 0) {     /* out -= in */
         --out->tv_sec;
         out->tv_usec += 1000000;
     }
     out->tv_sec -= in->tv_sec;
 }
 
 
 
void proc(char *ptr, ssize_t len, struct timeval *tvrecv)
 {
     int     hlenl, icmplen;
     double  rtt;
     struct ip *ip;
     struct icmp *icmp;
     struct timeval *tvsend;
	 
	struct hostent *he;
	char paddr[INET_ADDRSTRLEN];

	 //printf("previous node :%s \n",previousnode);
     ip = (struct ip *) ptr;      /* start of IP header */
     hlenl = ip->ip_hl << 2;      /* length of IP header */
     if (ip->ip_p != IPPROTO_ICMP)
         return;                  /* not ICMP */

     icmp = (struct icmp *) (ptr + hlenl);   /* start of ICMP header */
     if ( (icmplen = len - hlenl) < 8)
         return;                  /* malformed packet */

     if (icmp->icmp_type == ICMP_ECHOREPLY) {
         if (icmp->icmp_id != pid)
             return;                /* not a response to our ECHO_REQUEST */
         if (icmplen < 16)
             return;                /* not enough data to use */

         tvsend = (struct  timeval  *) icmp->icmp_data;
         tv_sub (tvrecv, tvsend);
         rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;
		 
		he = gethostbyname(previousnode);
		if (he == NULL) { 
		herror("gethostbyname");
		exit(1);
		}
		bzero(paddr,sizeof(paddr));

		
        printf ("%d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n",
                 icmplen,inet_ntop(he->h_addrtype,he->h_addr_list[0],paddr,INET_ADDRSTRLEN),
                 icmp->icmp_seq, ip->ip_ttl, rtt);
				 
		
		//printf("*********************************************************\n\n");
		
		
		

     } 
 }

void echo_request()
 {

	char src_mac[6],dst_mac[6];
	struct sockaddr_ll addr;
	char dst_ip[INET_ADDRSTRLEN], src_ip[INET_ADDRSTRLEN],ethernet_type[MAXLINE];
	void* buffer = (void*)malloc(ETH_PACKET_LEN);
	unsigned char* etherhead = buffer ;
	int i,send_result;
	struct ip *send_iphdr=(struct ip*) buffer+14;
	struct icmp *send_icmphdr =(struct icmp*) buffer+34;
	struct ethhdr *eh = (struct ethhdr *)etherhead;
	int     icmplen;
	            
	struct hostent *he;
	struct hwa_info	*hwa, *hwahead;
    struct sockaddr	*sa;
    char   *ptr;
    int    prflag,status;
    
	
	
	for (hwahead = hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next)
    {
        if (strncmp(hwa->if_name, "eth0",4) == 0)
        {
            
            if ((sa = hwa->ip_addr) != NULL)
            {
           
               
                memcpy(src_mac,hwa->if_haddr,6);
            }
            
            prflag = 0;
            i = 0;
            do {
                if (hwa->if_haddr[i] != '\0') {
                    prflag = 1;
                    break;
                }
            } while (++i < IF_HADDR);
            
           /*  if (prflag) {
                printf("Source MAC Address = ");
                ptr = hwa->if_haddr;
                i = IF_HADDR;
                do {
                    
                    printf("%.2x%s", *ptr++ & 0xff, (i == 1) ? " " : ":");
                    
                } while (--i > 0);
            } */
			printf("\n");
        }
        
    }
    free_hwa_info(hwahead);
	
	
	// Set destination MAC address: you need to fill these out
	dst_mac[0] = HWaddr.sll_addr[0];
	dst_mac[1] = HWaddr.sll_addr[1];
	dst_mac[2] = HWaddr.sll_addr[2]; 
	dst_mac[3] = HWaddr.sll_addr[3];
	dst_mac[4] = HWaddr.sll_addr[4];
	dst_mac[5] = HWaddr.sll_addr[5];
	dst_mac[6] = 0x00;
	dst_mac[7] = 0x00;

	he = gethostbyname(currentnode);
	if (he == NULL) { 
		herror("gethostbyname");
		exit(1);
	}
	bzero(src_ip,sizeof(src_ip));
	inet_ntop(he->h_addrtype,he->h_addr_list[0],src_ip,INET_ADDRSTRLEN);
	//printf("\n%s source ip\n",src_ip);
	
	
	he = gethostbyname(previousnode);
	if (he == NULL) { 
		herror("gethostbyname");
		exit(1);
	}
	bzero(dst_ip,sizeof(dst_ip));
	inet_ntop(he->h_addrtype,he->h_addr_list[0],dst_ip,INET_ADDRSTRLEN);
	//printf("\n%s destination ip \n",dst_ip);

	//ip header
	send_iphdr->ip_hl = 5;
	send_iphdr->ip_v = 4;
	send_iphdr->ip_tos = 0;
	send_iphdr->ip_len = htons(ETH_PAYLOAD_LEN);   // Total length of datagram (16 bits): IP header + ICMP header + ICMP data
	send_iphdr->ip_id = htons(0); // ID sequence number (16 bits): unused, since single datagram
	send_iphdr->ip_ttl = 255;
	send_iphdr->ip_off =0; 
	send_iphdr->ip_p = IPPROTO_ICMP;
	
	
	 // Source IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, src_ip, &(send_iphdr->ip_src))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Destination IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, dst_ip, &(send_iphdr->ip_dst))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

	
    send_iphdr->ip_sum = 0;
    send_iphdr->ip_sum = in_cksum((uint16_t *) send_iphdr, 20);

	pid = getpid() & 0xffff; 
	
	//icmp header
	send_icmphdr->icmp_type = ICMP_ECHO;
	send_icmphdr->icmp_code = 0;
	send_icmphdr->icmp_id = pid;
	send_icmphdr->icmp_seq = nsent++;
    memset (send_icmphdr->icmp_data, 0xa5, DATALEN); /* fill with pattern */
    Gettimeofday ((struct timeval *) send_icmphdr->icmp_data, NULL);

    icmplen = 8 + DATALEN;           /* checksum ICMP header and data */
    send_icmphdr->icmp_cksum = 0;
    send_icmphdr->icmp_cksum = in_cksum ((u_short *)send_icmphdr, icmplen);
	
	
	//Fill out ethernet frame header.
    addr.sll_family   = PF_PACKET;
    addr.sll_protocol = htons(ETH_P_IP);
    addr.sll_ifindex  = 2;
    addr.sll_pkttype  = PACKET_OTHERHOST;
    addr.sll_halen    = ETH_ALEN;
    
	memcpy (addr.sll_addr, dst_mac, 6);
    addr.sll_addr[6]  = 0x00;/*not used*/
    addr.sll_addr[7]  = 0x00;/*not used*/
	
	
	//Ethernet Buffer = Ethernet Header(src mac + dest mac + ethernet type) + Payload(IP header + ICMP header + ICMP data)
	
	
	memcpy ((void *)buffer, (void *)dst_mac, 6);
	memcpy ((void *)(buffer + 6), (void *)src_mac, 6);
	eh->h_proto = htons(ETH_P_IP);
	

	// IPv4 header
	memcpy ((void *)(buffer + 14), (void *)send_iphdr, sizeof(struct ip));
	
	// ICMP header
	memcpy ((void *)(buffer + 14 + 20), (void *)send_icmphdr, icmplen);
	
	if(pingendflag != 0){
	send_result = sendto(pf_socket, buffer, ETH_PACKET_LEN, 0,
                                 (struct sockaddr*)&addr, sizeof(addr));
								 
	
    if (send_result == -1) 
	{
        printf("Sending error : %d",errno);
        exit(1);
                
    }
	
	}
	free(buffer);
	
 }

void sig_alrm (int signo)
 {

	echo_request();
	alarm(1);
    return;
 }
 
int sendmulticastmsg(char* multicastmsg){

	int sendbytes;
	socklen_t salen;
	struct sockaddr_in multicastaddr;
			
	bzero(&multicastaddr,sizeof(multicastaddr));
	multicastaddr.sin_family = AF_INET;
	multicastaddr.sin_port = htons(MPORT);
	multicastaddr.sin_addr.s_addr = inet_addr(MULTICAST_IP);
	salen = sizeof(struct sockaddr);
			
	
	printf("Node %s. Sending :<%s> \n",currentnode,multicastmsg);
	sendbytes = sendto(udpsend_socket, multicastmsg, MAXLINE, 0, (struct sockaddr*)&multicastaddr, sizeof(multicastaddr));

	//printf("multicast message send \n");
	if (sendbytes < 0)
	{
		printf("sendto error for multicast message: %d\n", errno);
	}
	return 0;
}


void multicastreply(char* multicastmsg){
	
	sprintf(multicastmsg, "<<<<<Node %s .I am a member of the group. >>>>> \n", currentnode);
	sendmulticastmsg(multicastmsg);
	
}

int main(int argc, char const *argv[])
{
	
	
	int i,len,l;
	const int on = 1;
	char packet[MAXLINE];
	char dest[MAXLINE];
	int maxfdp,nready,fdp,rt_data;
    fd_set rset;
	char rtbuffer[MAXLINE];
    struct sockaddr_in rtaddr;
	char    time_buff[MAXLINE];
    time_t ticks;
	struct hostent *he;
	int count = 0;
	int recvlen,ptr;
	char* packet1;
	socklen_t socklen,sock_len;
	
	char* next_ptr;
	char str[INET_ADDRSTRLEN],nextip[INET_ADDRSTRLEN],previousip[INET_ADDRSTRLEN];
	struct hostent *he1;
	struct sockaddr_in nexthopaddr,previoushopaddr;

					
	char multicast[16];
	char temp[MAXLINE];
	struct sockaddr_in sasend, sarecv,multicastaddr;
	socklen_t salen,mclen;
	
	struct sockaddr_in pgaddr;
	struct timeval tval;
	int recvbytes;
	char pgbuff[MAXLINE];
	int pingcount=0;
    int flag;
	char multicastmsg[MAXLINE];
	int multicastbyte;
	char multicastbuff[MAXLINE];
	struct sockaddr_in mcaddr;
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
	

	bzero(&multicastaddr,sizeof(multicastaddr));
	
	multicastaddr.sin_family = AF_INET;
	multicastaddr.sin_port = htons(MPORT);
	multicastaddr.sin_addr.s_addr = inet_addr(MULTICAST_IP);
	salen = sizeof(struct sockaddr);

	bind(udprecv_socket, (struct sockaddr*)&multicastaddr, salen);
	
	if(argc >= 2)
	{   //limiting number of nodes entered by user to be 20
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
			make_packet(argc,argv,dest);
		
			
			
	}

	
	Signal(SIGALRM, sig_alrm);
	
	while(1)
    {
        FD_ZERO(&rset);
        FD_SET(rt, &rset);
        FD_SET(pg, &rset);
		FD_SET(udprecv_socket, &rset);
        fdp = max(rt,pg) ;
		maxfdp = max(fdp,udprecv_socket);
   
        if ((nready = select(maxfdp+1, &rset, NULL, NULL, NULL)) < 0)
        {
            //printf(" Select error: %d\n", errno);
            continue;
        }
		
		//if packet is received on route traversal socket
		if (FD_ISSET(rt, &rset))
        {
		
			memset(rtbuffer, 0, sizeof(MAXLINE));
            sock_len = sizeof(struct sockaddr);
            rt_data = Recvfrom(rt, rtbuffer , MAXLINE, 0, (struct sockaddr *)&rtaddr, &sock_len);
            if(rt_data < 0)
            {
                printf("error in receiving from unix domain socket\n");
            }
			
			
			struct iphdr *rt_recv_hdr = (struct iphdr*)rtbuffer;
			char* rt_recv_payload = rtbuffer + sizeof(struct iphdr);
			recvlen = rt_recv_payload[0];
			ptr = rt_recv_payload[1];
			
			if(ntohs(rt_recv_hdr->id) == IDENTIFICATION)
			{
			
					
					he = gethostbyaddr(&(rt_recv_hdr->saddr),sizeof(rt_recv_hdr->saddr),AF_INET);
					strcpy(previousnode,he->h_name);
					printf("Previous node IP %s \n",inet_ntop(AF_INET,he->h_addr_list[0],previousip,INET_ADDRSTRLEN));
					inet_pton(AF_INET,previousip, &previoushopaddr.sin_addr);
					
					printf("*********************************************************\n\n");
					printf("Received Valid Packet from source %s \n\n",he->h_name);

					gethostname(currentnode, sizeof currentnode);

					ticks = time(NULL);
					snprintf(time_buff, sizeof(time_buff), "%.24s\r\n", ctime(&ticks));

					printf("<%s> received source routing packet from %s\n",time_buff,he->h_name);
				
					count++;
					
					if(count == 1)
					{
						printf("%s node is visited for the first time \n\n",currentnode);
	
						memcpy(&multicast,&rt_recv_payload[recvlen-6],4);

						inet_ntop(AF_INET,multicast,temp,INET_ADDRSTRLEN);
				
						//joining multicast group
						bzero(&sasend,sizeof(sasend));
						sasend.sin_family = AF_INET;
						sasend.sin_port = htons(MPORT);
						sasend.sin_addr.s_addr = inet_addr(temp);
						salen = sizeof(struct sockaddr);
						
						//memcpy(&sarecv, &sasend, salen);
						
						Mcast_join(udprecv_socket, (struct sockaddr*)&sasend, salen, NULL, 0);
						Mcast_set_loop(udprecv_socket, 1);

						setsockopt(udprecv_socket, IPPROTO_IP, 1, (void *) &on, sizeof(on));
						
						printf("Joined Multicast Group \n");
						//mcast_join(udprecv_socket, (struct sockaddr*)&sasend, salen, NULL, 0); 

					}
					else
					{
						printf("%s node is visited for the %d time \n\n",currentnode,count);
					}
					
						//sending packet to next node
						
						
						//last node
						if(rt_recv_payload[1] == (recvlen-6)){
							
							printf("Last Node \n\n");
							printf("*********************************************************\n\n");
							printf("call areq now \n");
							socklen = sizeof(struct sockaddr_in);
							areq((struct sockaddr *)&previoushopaddr,socklen,&HWaddr);
							
							
							flag=0;
								
								for(l=0;l<10;l++)
								{
								
									if(strcmp(ping_list[l],previousip) == 0)
									{
										flag=1;
										break;
									}
								}   
								 	
								if(flag==1)
								{
									printf("ping already processed from this node to previous node \n");
									printf("previous ping continuing..... \n");
									continue;
								}
								else if(flag == 0)
								{
									strcpy(ping_list[pingcount],previousip);
									pingcount++;
									printf("PING %s (%s): %d data bytes\n\n", previousip, previousip, DATALEN);

									sig_alrm (SIGALRM); 
									sleep(5);
									sprintf(multicastmsg, "<<<<< This is node %s .  Tour has ended .  Group members please identify yourselves. >>>>> \n", currentnode);
									sendmulticastmsg(multicastmsg);
								}
							continue;
						
						}
						else
						{
								next_ptr = rt_recv_payload + rt_recv_payload[1];

								memcpy(str,next_ptr,4);
								
								printf("Next node IP %s \n",inet_ntop(AF_INET,str,nextip,INET_ADDRSTRLEN));
								
								
								inet_pton(AF_INET,nextip, &nexthopaddr);
								he1 = gethostbyaddr(&nexthopaddr, sizeof nexthopaddr, AF_INET);
								
								printf("next node vm %s \n",he1->h_name);
								send_packet(currentnode,he1->h_name,rtbuffer);
								
								printf("call areq now \n");
								
								socklen = sizeof(struct sockaddr_in);
								
								areq((struct sockaddr *)&previoushopaddr,socklen,&HWaddr);

								printf("Pinging previous node \n");
								
								flag=0;
								
								for(l=0;l<10;l++)
								{
								
									if(strcmp(ping_list[l],previousip) == 0)
									{
										flag=1;
										break;
									}
								}   
								 	
								if(flag==1)
								{
									printf("ping already processed from this node to previous node \n");
									continue;
								}
								else if(flag == 0)
								{
									strcpy(ping_list[pingcount],previousip);
									pingcount++;
									printf("PING %s (%s): %d data bytes\n\n", previousip, previousip, DATALEN);
									sig_alrm (SIGALRM); 
								
								}
							
									
							 continue;	
						}

								
			}
					
			
			else
			{
					printf("Received Invalid Packet.Ignoring Packet \n");
			}
		}
		
		else if (FD_ISSET(pg, &rset))
        {
			
			memset(pgbuff, 0, sizeof(pgbuff));
			memset (&pgaddr, 0, sizeof (pgaddr));
			socklen_t pglen = sizeof(pgaddr);
			if(pingendflag != 1){
			recvbytes = recvfrom(pg, pgbuff, IP_MAXPACKET, 0, (struct sockaddr*)&pgaddr, &pglen);
			Gettimeofday (&tval, NULL);
			proc(pgbuff, recvbytes,&tval);
			}
			continue;
		
		} 
		
		//if packet is received on unix domain socket
		else if (FD_ISSET(udprecv_socket, &rset))
        {

			memset(multicastbuff, 0, sizeof(multicastbuff));
			memset (&mcaddr, 0, sizeof (mcaddr));
			socklen_t mclen = sizeof(mcaddr);
			multicastbyte = recvfrom(udprecv_socket, multicastbuff, MAXLINE, 0, (struct sockaddr*)&mcaddr, &mclen);
			printf("Node %s. Received <%s> \n",currentnode,multicastbuff);
			pingendflag = 1;
			multicastreply(multicastbuff);
			
		}
	}
}