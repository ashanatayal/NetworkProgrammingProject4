

 uint16_t in_cksum (uint16_t * addr, int len)
 {
     int     nleft = len;
     uint32_t sum = 0;
     uint16_t *w = addr;
     uint16_t answer = 0;

     while (nleft > 1) {
         sum += *w++;
         nleft -= 2;
     }
       
     if (nleft == 1) {
         * (unsigned char *) (&answer) = * (unsigned char *) w;
         sum += answer;
     }

         /* add back carry outs from top 16 bits to low 16 bits */
     sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
     sum += (sum >> 16);     /* add carry */
     answer = ~sum;     /* truncate to 16 bits */
     return (answer);
 }

int echo_request(char currentnode[MAXLINE],char previousnode[MAXLINE])
{
	struct ifreq ifr;
	uint8_t *src_mac,*dst_mac,*data,*send_ether_frame;
	struct sockaddr_ll device;
	char *interface,*dst_ip,*target, *src_ip;
	struct addrinfo hints, *res;
	int i,status,datalen,*ip_flags,frame_length,timeout,bytes;
	struct sockaddr_in *ipv4;
	void *tmp;
	struct iphdr send_iphdr;
	struct icmp send_icmphdr, *recv_icmphdr;
	int     icmplen;
	struct 	timeval wait, t1, t2;
	int     nsent;                  /* add 1 for each sendto() */
	pid_t   pid;                    /* our PID */
	int done=0;
	struct hostent *he;
	struct timezone tz;
	
	// Allocate memory for various arrays.
	src_mac = allocate_ustrmem (6);
	dst_mac = allocate_ustrmem (6);
	interface = allocate_strmem (40);
	target = allocate_strmem (40);
	src_ip = allocate_strmem (INET_ADDRSTRLEN);
	dst_ip = allocate_strmem (INET_ADDRSTRLEN);
	data = allocate_ustrmem (IP_MAXPACKET);
	ip_flags = allocate_intmem (4);
	send_ether_frame = allocate_ustrmem (IP_MAXPACKET);
	
	// Interface to send packet through.
	strcpy (interface, "eth0");
	
	// Use ioctl() to look up interface name and get its MAC address.
	memset (&ifr, 0, sizeof (ifr));
	snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
	if (ioctl (pf_socket, SIOCGIFHWADDR, &ifr) < 0) {
	perror ("ioctl() failed to get source MAC address ");
	return (EXIT_FAILURE);
	}
	
	// Copy source MAC address.
	memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6);
	
	// Report source MAC address to stdout.
	printf ("MAC address for interface %s is ", interface);
	for (i=0; i<5; i++) {
	printf ("%02x:", src_mac[i]);
	}
	printf ("%02x\n", src_mac[5]);
	
	
	src_mac[6] = 0x00;
	src_mac[7] = 0x00;
	
	// Find interface index from interface name and store index in
	// struct sockaddr_ll device, which will be used as an argument of sendto().
	memset (&device, 0, sizeof (device));
	if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
	perror ("if_nametoindex() failed to obtain interface index ");
	exit (EXIT_FAILURE);
	}
	printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);
	
	 // Set destination MAC address: you need to fill these out
	dst_mac[0] = 0x00;
	dst_mac[1] = 0x0c;
	dst_mac[2] = 0x29; 
	dst_mac[3] = 0x49;
	dst_mac[4] = 0x3f;
	dst_mac[5] = 0x5b;
	
	dst_mac[6] = 0x00;
	dst_mac[7] = 0x00;
	
	he = gethostbyname(currentnode);
	if (he == NULL) { 
		herror("gethostbyname");
		exit(1);
	}
	bzero(src_ip,sizeof(src_ip));
	inet_ntop(he->h_addrtype,he->h_addr_list[0],src_ip,INET_ADDRSTRLEN);
	printf("\n%s source ip:-\n",src_ip);
	
	he = gethostbyname(previousnode);
	if (he == NULL) { 
		herror("gethostbyname");
		exit(1);
	}
	bzero(dst_ip,sizeof(dst_ip));
	inet_ntop(he->h_addrtype,he->h_addr_list[0],dst_ip,INET_ADDRSTRLEN);
	printf("\n%s dettination ip:-\n",dst_ip);

	
	
	// Fill out sockaddr_ll.
	device.sll_family = AF_PACKET;
	memcpy (device.sll_addr, dst_mac, 6);
	device.sll_halen = 6;
	
	pid = getpid() & 0xffff;     /* ICMP ID field is 16 bits */

	// IPv4 header
	send_iphdr.ihl = 5;
	send_iphdr.version = 4;
	send_iphdr.tos = 0;
	send_iphdr.tot_len = htons (IP4_HDRLEN + ICMP_HDRLEN + datalen);   // Total length of datagram (16 bits): IP header + ICMP header + ICMP data
	send_iphdr.id = htons(IDENTIFICATION); // ID sequence number (16 bits): unused, since single datagram
	send_iphdr.ttl = 255;
	send_iphdr.protocol = IPPROTO_ICMP;
	send_iphdr.check = 0; 
    send_iphdr.check = in_cksum ((u_short *) &send_iphdr, datalen+8);
	send_iphdr.saddr=inet_addr(src_ip);
    send_iphdr.saddr=inet_addr(dst_ip);

	
	//icmp data
	send_icmphdr.icmp_type = ICMP_ECHO;
	send_icmphdr.icmp_code = 0;
	send_icmphdr.icmp_id = pid;
	send_icmphdr.icmp_seq = nsent++;
    memset (send_icmphdr.icmp_data, 0xa5, datalen); /* fill with pattern */
    Gettimeofday ((struct timeval *) send_icmphdr.icmp_data, NULL);

    icmplen = 8 + datalen;           /* checksum ICMP header and data */
    send_icmphdr.icmp_cksum = 0;
    send_icmphdr.icmp_cksum = in_cksum ((u_short *) &send_icmphdr, icmplen);

	
	// Fill out ethernet frame header.
	
	// Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + ICMP header + ICMP data)
	frame_length = 6 + 6 + 2 + IP4_HDRLEN + ICMP_HDRLEN + datalen;
	
	// Destination and Source MAC addresses
	memcpy (send_ether_frame, dst_mac, 6);
	memcpy (send_ether_frame + 6, src_mac, 6);
	
	send_ether_frame[12] = ETH_P_IP / 256;
	send_ether_frame[13] = ETH_P_IP % 256; 
	
	// Next is ethernet frame data (IPv4 header + ICMP header + ICMP data).
	
	// IPv4 header
	memcpy (send_ether_frame + ETH_HDRLEN, &send_iphdr, IP4_HDRLEN);
	
	// ICMP header
	memcpy (send_ether_frame + ETH_HDRLEN + IP4_HDRLEN, &send_icmphdr, ICMP_HDRLEN);
	

		// SEND

		// Send ethernet frame to socket.
		
		printf("SENDING ECHO REQUEST ON PF_PACKET SOCKET \n");
		if ((bytes = sendto(pf_socket, send_ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
		  perror ("sendto() failed ");
		  exit (EXIT_FAILURE);
		} 

		printf("Send Done \n");
		
	

	return 0;
	
}