

#include "unp.h"
#include <linux/if_ether.h>
#include <setjmp.h>
#include <net/ethernet.h>
#include <sys/un.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <errno.h>
#include "hw_addrs.h"

#include <linux/if_packet.h>

#define PROTOCOL 62357     //Unique protocol
#define SOURCEPORT 13855
#define SERVERPORT 13854
#define ARP_PATH "kimi"   //Unique sun path
#define ETH_HDRLEN 14      // Ethernet header length
#define IP4_HDRLEN 20      // IPv4 header length
#define ARP_HDRLEN 30      // ARP header length
#define ARPOP_REQUEST 1    // Taken from <linux/if_arp.h>
#define ARPOP_REPLY 2
#define GROUP_ID 3571       //Group Unique ID for the team
#define ETH_FRAME_LENGTH 1500
#define INCOMPLETE -1
#define COMPLETE 1
// Function prototypes
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);



/*Global Declarations*/
char ip_canonical[INET_ADDRSTRLEN];
unsigned char mac_address[IF_HADDR];
int if_index;
int pf_packet;
int unixdomain_socket;
int acceptfd;
int cachecount;
int domain_packetcount;

// Define a struct for ARP header
typedef struct _arp_hdr arp_hdr;
struct _arp_hdr {
    uint16_t id;
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t sender_mac[6];
    char sender_ip[16];
    uint8_t target_mac[6];
    char target_ip[16];
}*parphdr_send,*parphdr_rcv;

//typedef struct _Ethernet_hdr Ethernet_Hdr;
struct Ethernet_hdr{
    unsigned char destMAC[6];
    unsigned char sourceMAC[6];
    uint16_t frame_type;
}*pethframehdr_send,*pethframehdr_rcv;



struct arp_cache{
    int sll_ifindex;
    int connfd;
    unsigned short sll_hatype;
    unsigned char sll_addr[6];
    unsigned char IP[INET_ADDRSTRLEN];
    int valid;
    
}arpcache[50];

void ntop_mac(char mac_address[6]) //Function to print MAC_ADDRESSES
{
    char* ptr;
    int i;
    ptr=mac_address;
    
    for(i=0;i<6;i++)
    {
        printf("%.2x%s", *ptr++ & 0xff, (i == 5) ? " " : ":");
        
    }
    
    printf("\n");
}

int printEthArpFrame(struct Ethernet_hdr* printEthHdr ,arp_hdr* printARPhdr )
{
    printf("Ethernet Frame-----------------\n");
    
    
    printf("\n Source MAC Address : ");
    ntop_mac(printEthHdr->sourceMAC);

    printf("\n Destination MAC Address : ");
    ntop_mac(printEthHdr->destMAC);
    
    printf("\n Protocol=  %d \n",ntohs(printEthHdr->frame_type));
    
    printf("ARP Message--------- \n");
    if(ntohs(printARPhdr->opcode)==ARPOP_REPLY)
       {
       printf("\n ARP REPLY \n");
       }
    else
       {printf("\n ARP REQUEST \n");}
    printf("\n Source Ip %s \n",printARPhdr->sender_ip);
    printf("\n Sender MAC Address = ");
    ntop_mac(printARPhdr->sender_mac);

    printf("\n Destination Ip %s \n",printARPhdr->target_ip);
    printf("\n Target MAC Address = ");
    ntop_mac(printARPhdr->target_mac);
    printf("\n Identification \n : %d",ntohs(printARPhdr->target_mac));
   
       
    printf("\n");
    

    
    
    return 0;
}







void print_cache(int cache_index)
{   printf("\n Cache Table -------------------------------------------\n");
    printf("\n Interface Index : %d\n",arpcache[cache_index].sll_ifindex);
    printf("\n HA Type : %d\n",arpcache[cache_index].sll_hatype);
    printf("\n IP Address: %s\n",arpcache[cache_index].IP);
    if(arpcache[cache_index].valid==COMPLETE)
    {    printf("\n MAC ADDRESS :              ");
        ntop_mac(arpcache[cache_index].sll_addr);
    }
    printf("\n---------------------------------------------------------\n");
}

int ip_hwaddr()
{
    struct hwa_info	*hwa, *hwahead;
    struct sockaddr	*sa;
    char   *ptr;
    int    i, prflag;
    
    printf("\n");
    
    for (hwahead = hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next)
    {
        if (strncmp(hwa->if_name, "eth0",4) == 0)
        {
            printf("The IP address and Ethernet MAC address pairs for interface eth0 are : \n");
            printf("%s :%s", hwa->if_name, ((hwa->ip_alias) == IP_ALIAS) ? " (alias)\n" : "\n");
            
            if ( (sa = hwa->ip_addr) != NULL)
            {
                printf("           IP address is %s \n", Sock_ntop_host(sa, sizeof(*sa)));
                if_index=hwa->if_index;
                
                memcpy(ip_canonical,Sock_ntop_host(sa, sizeof(*sa)),16);
                memcpy(mac_address,hwa->if_haddr,6);
            }
            
            prflag = 0;
            i = 0;
            do {
                if (hwa->if_haddr[i] != '\0') {
                    prflag = 1;
                    break;
                }
            } while (++i < IF_HADDR);
            
            if (prflag) {
                printf("           MAC Address = ");
                ptr = hwa->if_haddr;
                i = IF_HADDR;
                //int j=0;
                do {
                    
                    printf("%.2x%s", *ptr++ & 0xff, (i == 1) ? " " : ":");
                    
                } while (--i > 0);
            }
            
            printf("\n           Interface index is %d \n",if_index);
            
        }
        
    }
    free_hwa_info(hwahead);
    printf("\n");
    
    return 0;
}

// Allocate memory for an array of chars.
char *
allocate_strmem (int len)
{
    void *tmp;
    
    if (len <= 0) {
        fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
        exit (EXIT_FAILURE);
    }
    
    tmp = (char *) malloc (len * sizeof (char));
    if (tmp != NULL) {
        memset (tmp, 0, len * sizeof (char));
        return (tmp);
    } else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
        exit (EXIT_FAILURE);
    }
}

// Allocate memory for an array of unsigned chars.
uint8_t * allocate_ustrmem (int len)
{
    void *tmp;
    
    if (len <= 0) {
        fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
        exit (EXIT_FAILURE);
    }
    
    tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
    if (tmp != NULL) {
        memset (tmp, 0, len * sizeof (uint8_t));
        return (tmp);
    } else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
        exit (EXIT_FAILURE);
    }
}

int find_mac_address(char resolve_ip[INET_ADDRSTRLEN],char src_ip[INET_ADDRSTRLEN])
{
    int j;
    struct hwa_info	*hwa, *hwahead;
    char   *ptr;
    int    i;
    /*target address*/
    struct sockaddr_ll socket_address;
    unsigned char src_mac[6];
  
    int send_result = 0;
    
    for (hwahead = hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next)
    {
        if (strncmp(hwa->if_name, "eth0",4) == 0)
        {
        ptr = hwa->if_haddr;
        i = IF_HADDR;
        j=0;
        /*Loading source Mac Address*/
        do{
            src_mac[j] = *ptr++ & 0xff;
        } while (--i > 0 && j++ < 5);
        
        
        
        /*buffer for ethernet frame*/
        void* buffer = (void*)malloc(ETH_FRAME_LENGTH);
        
        /*pointer to ethenet header*/
        //unsigned char* etherhead = buffer;
        pethframehdr_send = buffer;
        
        /*userdata in ethernet frame*/
        parphdr_send = (buffer + sizeof(struct Ethernet_hdr));
        
        
        
        /*other host MAC address*/
        unsigned char dest_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        // memcpy(buffer,src_mac,6);
        //memcpy(buffer+6,dest_mac,6);
        pethframehdr_send->frame_type=htons(PROTOCOL);
        
        parphdr_send->id=htons(GROUP_ID);
        parphdr_send->htype= htons(1);
        parphdr_send->ptype = htons(0x800);
        parphdr_send->hlen = htons(6);
        parphdr_send->plen = htons(4);
        parphdr_send->opcode = htons(ARPOP_REQUEST);
        
        memcpy(parphdr_send->sender_mac,src_mac,ETH_ALEN);
        memcpy(parphdr_send->sender_ip,src_ip,16);
        
        memset(parphdr_send->target_mac,0,ETH_ALEN);
        memcpy(parphdr_send->target_ip,resolve_ip,16);
        
        /*RAW communication*/
        socket_address.sll_family   = PF_PACKET;
        /*we don't use a protocoll above ethernet layer
         ->just use anything here*/
        socket_address.sll_protocol = htons(PROTOCOL);
        
        /*index of the network device
         see full code later how to retrieve it*/
        socket_address.sll_ifindex  = hwa->if_index;
        
        /*ARP hardware identifier is ethernet*/
        socket_address.sll_hatype   = 1;
        
        /*target is another host*/
        socket_address.sll_pkttype  = PACKET_BROADCAST;
        
        /*address length*/
        socket_address.sll_halen    = ETH_ALEN;
        /*MAC - begin*/
        socket_address.sll_addr[0]  = 0xff;
        socket_address.sll_addr[1]  = 0xff;
        socket_address.sll_addr[2]  = 0xff;
        socket_address.sll_addr[3]  = 0xff;
        socket_address.sll_addr[4]  = 0xff;
        socket_address.sll_addr[5]  = 0xff;
        /*MAC - end*/
        socket_address.sll_addr[6]  = 0x00;/*not used*/
        socket_address.sll_addr[7]  = 0x00;/*not used*/
        
        /*set the frame header*/
        memcpy((void*)buffer, (void*)dest_mac, ETH_ALEN);
        memcpy((void*)(buffer+ETH_ALEN), (void*)src_mac, ETH_ALEN);
        /*send the packet*/
        send_result = sendto(pf_packet, buffer, ETH_FRAME_LENGTH, 0,
                             (struct sockaddr*)&socket_address, sizeof(socket_address));
        if (send_result == -1) {
            printf("Sending error : %d",errno);
            exit(1);
            
        }
        
        printf("\n Broadcast message sent to find MAC addess \n");
            printEthArpFrame(pethframehdr_send,parphdr_send);
        
        
        }
    }

    return 0;
    
}


int check_cache(char resolve_ip[INET_ADDRSTRLEN])
{
    int i;
    for(i=0;i<40;i++)
    {
        if(strcmp(arpcache[i].IP,resolve_ip)==0)
        {
            if(arpcache[i].valid==1)
            {
                printf("\n IP address %s is present in AREP cache at entry %d",arpcache[i].IP,i);
                return i;
            }
        }
    }
    
    return -1;
    
    
}




int check_unixpacket(struct sockaddr_un recvip,char resolve_ip[INET_ADDRSTRLEN],char src_ip[INET_ADDRSTRLEN])
{
    int index;
    index=check_cache(resolve_ip);
    if(index!=-1)
    {
        printf("\n Cache Entry found at index %d \n",index);
        int nbytes_send=0;
        printf("\n Sending resolved MAC address to the Tour Module \n");
        if((nbytes_send = write(acceptfd,arpcache[index].sll_addr, 6))<0)
        {
            
            printf(" Error in writing to the connection socket descriptor \n");
            
        }
        printf("\n Resolved adress sent. Closing file descriptor \n");
        Close(acceptfd);
        return 1;
        
    }
    
    else if (index==-1)
    {
        printf("\n Cache Entry not found. Updating incomplete entry in the cache \n");
        
        /* Cache Entry Partial Updation */
        
        
        arpcache[cachecount].sll_ifindex=1;
        arpcache[cachecount].connfd=acceptfd;
        arpcache[cachecount].sll_hatype=1;
        strcpy(arpcache[cachecount].IP,resolve_ip);
        arpcache[cachecount].valid=INCOMPLETE;
        print_cache(cachecount);
        
        printf("\n Broadcasting To resolve IP address %s \n",src_ip);
        domain_packetcount=1;
        find_mac_address(resolve_ip,src_ip);
        return 0;
    }
    return 0;
    
}

int send_arp_reply()
{
    
    
    int j;
    struct hwa_info	*hwa, *hwahead;
    char   *ptr;
    int    i;
    /*target address*/
    struct sockaddr_ll socket_address;
    unsigned char src_mac[6];
    
    int send_result = 0;
    printf("\n Sending ARP reply \n");
    
    for (hwahead = hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next)
    {
        if (strncmp(hwa->if_name, "eth0",4) == 0)
        {
            ptr = hwa->if_haddr;
            i = IF_HADDR;
            j=0;
            /*Loading source Mac Address*/
            do{
                src_mac[j] = *ptr++ & 0xff;
            } while (--i > 0 && j++ < 5);
            
            
            
            /*buffer for ethernet frame*/
            void* buffer = (void*)malloc(ETH_FRAME_LENGTH);
            
            /*pointer to ethenet header*/
            //unsigned char* etherhead = buffer;
            pethframehdr_send = buffer;
            
            /*userdata in ethernet frame*/
            parphdr_send = (buffer + sizeof(struct Ethernet_hdr));
            
            
            
            /*other host MAC address*/
            //unsigned char dest_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
            // memcpy(buffer,src_mac,6);
            //memcpy(buffer+6,dest_mac,6);
            pethframehdr_send->frame_type=htons(PROTOCOL);
            
            parphdr_send->id=parphdr_rcv->id;
            parphdr_send->htype= htons(1);
            parphdr_send->ptype = htons(0x800);
            parphdr_send->hlen = htons(6);
            parphdr_send->plen = htons(4);
            parphdr_send->opcode = htons(ARPOP_REPLY);
            
            memcpy(parphdr_send->sender_mac,src_mac,ETH_ALEN);
            memcpy(parphdr_send->sender_ip,ip_canonical,16);
            
            memcpy(parphdr_send->target_mac,parphdr_rcv->sender_mac,ETH_ALEN);
            memcpy(parphdr_send->target_ip,parphdr_rcv->sender_ip,16);
            
            /*RAW communication*/
            socket_address.sll_family   = PF_PACKET;
            /*we don't use a protocoll above ethernet layer
             ->just use anything here*/
            socket_address.sll_protocol = htons(PROTOCOL);
            
            /*index of the network device
             see full code later how to retrieve it*/
            socket_address.sll_ifindex  = hwa->if_index;
            
            /*ARP hardware identifier is ethernet*/
            socket_address.sll_hatype   = 1;
            
            /*target is another host*/
            socket_address.sll_pkttype  = PACKET_BROADCAST;
            
            /*address length*/
            socket_address.sll_halen    = ETH_ALEN;
            /*MAC - begin*/
            socket_address.sll_addr[0]  = parphdr_rcv->sender_mac[0];
            socket_address.sll_addr[1]  = parphdr_rcv->sender_mac[1];
            socket_address.sll_addr[2]  = parphdr_rcv->sender_mac[2];
            socket_address.sll_addr[3]  = parphdr_rcv->sender_mac[3];
            socket_address.sll_addr[4]  = parphdr_rcv->sender_mac[4];
            socket_address.sll_addr[5]  = parphdr_rcv->sender_mac[5];
            /*MAC - end*/
            socket_address.sll_addr[6]  = 0x00;/*not used*/
            socket_address.sll_addr[7]  = 0x00;/*not used*/
            
            
            /*set the frame header*/
            /*set the frame header*/
            memcpy((void*)buffer, (void*)parphdr_rcv->sender_mac, ETH_ALEN);
            memcpy((void*)(buffer+ETH_ALEN), (void*)src_mac, ETH_ALEN);
            /*send the packet*/
            send_result = sendto(pf_packet, buffer, ETH_FRAME_LENGTH, 0,
                                 (struct sockaddr*)&socket_address, sizeof(socket_address));
            if (send_result == -1) {
                printf("Sending error : %d",errno);
                exit(1);
                
            }
            
            printf("\n ARP reply Packet Sent to source module ARP \n");
            printEthArpFrame(pethframehdr_send,parphdr_send);
            
            
            
        }
    }
    
     return 0;

}
int process_arp_request()
{
    int cache_index;
 
    if(strcmp(ip_canonical,parphdr_rcv->target_ip)==0)
    {
        printf("\n ARP request arrived. VM is the target vm and the IP to be resolved is %s ",parphdr_rcv->target_ip);
        printEthArpFrame(pethframehdr_rcv,parphdr_rcv);
        send_arp_reply();
        
        printf("Updating Sender Cache");
        arpcache[cachecount].sll_ifindex=1;
        arpcache[cachecount].sll_hatype=1;
        strcpy(arpcache[cachecount].IP,parphdr_rcv->sender_ip);
        arpcache[cachecount].valid=COMPLETE;
        memcpy(arpcache[cachecount].sll_addr,parphdr_rcv->sender_mac,6);
        print_cache(cachecount);
        cachecount++;
        
        
        return 0;
    }
    
    else if(strcmp(ip_canonical,parphdr_rcv->target_ip)!=0)
    {
        
        printf("\n ARP Request arrived. Not the target VM \n");
        printEthArpFrame(pethframehdr_rcv,parphdr_rcv);
        printf("\n Checking if sender address is present in cache");
        cache_index=check_cache(parphdr_rcv->sender_ip);
        if(cache_index!=-1)
        {
            printf("\n Updating Sender Cache \n");
            arpcache[cache_index].sll_ifindex=1;
            arpcache[cache_index].sll_hatype=1;
            strcpy(arpcache[cache_index].IP,parphdr_rcv->sender_ip);
            arpcache[cache_index].valid=COMPLETE;
            memcpy(arpcache[cache_index].sll_addr,parphdr_rcv->sender_mac,6);
            print_cache(cache_index);
            
        }
        
        else if(cache_index==-1)
        {
            printf("\n Sender address not present in cache. Doing nothing \n");
        }
        return 0;
    }
    
      return 0;
    
}

int send_arp_unix()
{
    int nbytes_send=0;
    printf("\n Updating Cache of destination at source module \n");
    arpcache[cachecount].sll_ifindex=1;
    arpcache[cachecount].sll_hatype=1;
    strcpy(arpcache[cachecount].IP,parphdr_rcv->sender_ip);
    arpcache[cachecount].valid=COMPLETE;
    memcpy(arpcache[cachecount].sll_addr,parphdr_rcv->sender_mac,6);
    print_cache(cachecount);

    cachecount++;
    
    
    printf("\n Sending resolved MAC address  for IP %s  to the Tour Module \n",parphdr_rcv->sender_ip);
    printf("\n Resolved MAC address :  \n");
    ntop_mac(parphdr_rcv->sender_mac);
    if(nbytes_send = write(acceptfd,parphdr_rcv->sender_mac, 6)<0)
    {
        
        printf(" Error in writing to the connection socket descriptor \n");
        
    }
    printf("\n Resolved adress sent. Closing file descriptor \n");
    Close(acceptfd);
    return 0;
    
}
int process_arp_reply()
{
    if(strcmp(ip_canonical,parphdr_rcv->target_ip)==0)
    {
        printf("\n ARP reply received at the source ARP module ",parphdr_rcv->target_ip);
        printEthArpFrame(pethframehdr_rcv,parphdr_rcv);
        send_arp_unix();
        
        
        return 0;
    }
    
    else if(strcmp(ip_canonical,parphdr_rcv->target_ip)!=0) //Something has gone wrong
    {
        //Check for cache updation
        
        printf("\n ARP Reply arrived but not at the source ARP \n");
        
        return 0;
    }
    
    return 0;
}

int main(int argc, char *argv[])
{
    struct sockaddr_un arpaddr,recvip;
    struct sockaddr_ll receivepktAddr;
    arp_hdr* rcvframe;
   
    fd_set rset;
    
    int maxfdp,nready,nbytes;
    char resolve_ip[INET_ADDRSTRLEN];
    char sourceCanonicalIP[INET_ADDRSTRLEN];
    struct hostent *he;
    char odrvm[5];
    char **ip;
    domain_packetcount=0;
    //void* rcvbuffer = (void*)malloc(ETH_FRAME_LENGTH);
    //creating pf_packet socket - packet interface on device level.
    pf_packet = Socket(PF_PACKET, SOCK_RAW, htons(PROTOCOL));
    
    socklen_t pktlen = sizeof(receivepktAddr);
    //
    
    socklen_t rcvlen = sizeof(recvip);
    
    ip_hwaddr();
    if (pf_packet == -1)
    {
        printf("Error in creating pf_packet socket \n");
    }
    
    //creating unix domain socket
    
    
    unixdomain_socket= Socket(AF_LOCAL, SOCK_STREAM, 0);
    if(unixdomain_socket < 0)
    {
        printf("\n Unix Domain Socket creation error\n");
        
    }
    
    unlink(ARP_PATH);
    bzero(&arpaddr, sizeof(arpaddr));
    arpaddr.sun_family = AF_LOCAL;
    strcpy(arpaddr.sun_path, ARP_PATH);
    
    if(bind(unixdomain_socket, (struct sockaddr *)&arpaddr, sizeof(arpaddr))<0){
        printf("Unix Domain Socket bind error \n");
    }
    
    Listen(unixdomain_socket,50);
    //check on which socket request is coming through select
    while(1)
    {
        //printf("\n Waiting in While 1");
        FD_ZERO(&rset);
        FD_SET(pf_packet, &rset);
        FD_SET(unixdomain_socket, &rset);
        maxfdp = max(pf_packet,unixdomain_socket) +1;
        nready = Select(maxfdp, &rset, NULL, NULL, NULL);
        if (nready < 0)
        {
            printf(" Select error: %d\n", errno);
            continue;
        }
        
        //if request is received on unix domain socket
        if (FD_ISSET(unixdomain_socket, &rset))
        {
            if(domain_packetcount==1)
            {
                printf("\n Tour Module areq() closed the connection socket. Removing partial entry fromm cache table. \n");
                arpcache[cachecount].sll_ifindex=0;
                arpcache[cachecount].connfd=0;
                arpcache[cachecount].sll_hatype=0;
                bzero(&arpcache[cachecount].IP,INET_ADDRSTRLEN);
                arpcache[cachecount].valid=0;
                printf(" \n Cache entry emptied");
                print_cache(cachecount);
                domain_packetcount=0;
                cachecount=0;
                continue;
            }
            
            acceptfd=0;
            acceptfd = Accept(unixdomain_socket,(struct sockaddr *)&recvip, &rcvlen);
            printf("Packet received on  UNIX_SOCKET \n");
            if(nbytes = Read(acceptfd, resolve_ip, INET_ADDRSTRLEN)<=0)
                printf("\n Error in reading IP address %d \n",nbytes);
            printf("\n IP address to be resolved is %s \n ",resolve_ip);
            
            gethostname(odrvm, sizeof odrvm);
            printf("\n odrvm: %s\n", odrvm);
            
            //get arp odr canonical IP address
            
            
            he = gethostbyname(odrvm);
            if (he == NULL) { // do some error checking
                herror("gethostbyname");
                exit(1);
            }
            
            ip=he->h_addr_list;
            printf("\n source Canonical IP : %s \n",inet_ntop(he->h_addrtype,*ip,sourceCanonicalIP,sizeof(sourceCanonicalIP)));
            
            
            check_unixpacket(recvip,resolve_ip,sourceCanonicalIP);
            //return 0;
            
        }
        
        if (FD_ISSET(pf_packet, &rset))
        {
            printf("Packet received on  PF_SOCKET \n");
            
            struct sockaddr_ll rcv_pkt_addr;
            void* rcvbuffer = (void*)malloc(ETH_FRAME_LEN); /*Buffer for ethernet frame*/
            pethframehdr_rcv = rcvbuffer;
            
            /*userdata in ethernet frame*/
            parphdr_rcv = (rcvbuffer + sizeof(struct Ethernet_hdr));
            memset(&rcv_pkt_addr, 0, sizeof(rcv_pkt_addr));
            memset(rcvbuffer, 0, sizeof(rcvbuffer));
            
            socklen_t rcvlen = sizeof(rcv_pkt_addr);
            
            
          
            int length = 0; /*length of the received frame*/
            length = Recvfrom(pf_packet, rcvbuffer, ETH_FRAME_LEN, 0,(struct sockaddr*)&rcv_pkt_addr,&rcvlen);
            
            if (length == -1)
            {
                printf("receive error %d",errno);
                exit(1);
                
            }
            
            printf("Packet received on  PF_SOCKET of length %d bytes \n",length);
            //printf("\n The opcode is %d \n",ntohs(parphdr_rcv->opcode));
            if(ntohs(parphdr_rcv->opcode) == ARPOP_REQUEST)
            {
                printf("\n Processing ARP request \n");
                process_arp_request();
            }
            
            
            else if(ntohs(parphdr_rcv->opcode) == ARPOP_REPLY)
            {
                printf("\n Processing ARP reply \n");
                
                process_arp_reply();
            }
           
            
        }
        
        
    }
    
    return 0;
    
    
}