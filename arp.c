//
//  arp.c
//  
//
//  Created by Karthikeyan Swaminathan on 11/29/15.
//
//


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
#include <linux/if_arp.h>
#include <linux/if_packet.h>

#define PROTOCOL 562357
#define SOURCEPORT 13855
#define SERVERPORT 13854
#define ARP_PATH "/tmp/alonso"

/*Global Declarations*/
char ip_canonical[INET_ADDRSTRLEN];
unsigned char mac_address[IF_HADDR];
int if_index;


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

int main(int argc, char *argv[])
{
    struct sockaddr_un arpaddr;
    int unixdomain_socket;
    fd_set rset;
    int packet_socket;
    int maxfdp,nready;
    //creating pf_packet socket - packet interface on device level.
    packet_socket = socket(PF_PACKET, SOCK_RAW, htons(PROTOCOL));
    
    ip_hwaddr();
    if (packet_socket == -1)
    {
        printf("Error in creating pf_packet socket \n");
    }
    
    //creating unix domain socket
    
    
    unixdomain_socket= socket(AF_LOCAL, SOCK_STREAM, 0);
    if(unixdomain_socket < 0){
        printf("\n Unix Domain Socket creation error\n");
        
    }
    
    unlink(ARP_PATH);
    bzero(&arpaddr, sizeof(arpaddr));
    arpaddr.sun_family = AF_LOCAL;
    strcpy(arpaddr.sun_path, ARP_PATH);
    
    if(bind(unixdomain_socket, (struct sockaddr *)&arpaddr, sizeof(arpaddr))<0){
        printf("Unix Domain Socket bind error \n");
    }
    
    //check on which socket request is coming through select
    while(1)
    {
        FD_ZERO(&rset);
        FD_SET(packet_socket, &rset);
        FD_SET(unixdomain_socket, &rset);
        maxfdp = max(packet_socket,unixdomain_socket) +1;
        nready = select(maxfdp, &rset, NULL, NULL, NULL);
        if (nready < 0)
        {
            printf(" Select error: %d\n", errno);
            continue;
        }
        
        //if request is received on unix domain socket
        if (FD_ISSET(unixdomain_socket, &rset))
        {
         
            
            
        }
            
            if (FD_ISSET(packet_socket, &rset))
            {
                
               
                
                
            }
  
            
        
 
    
    
    
    
            }
            
            return 0;
    
      
}