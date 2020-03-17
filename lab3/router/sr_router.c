/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"


# define LOG_MSG(...) fprintf(stderr, __VA_ARGS__)

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  print_hdrs(packet,length);
  /* fill in code here */
  // if(len<sizeof(sr_ethernet_hdr_t))
  // {
  //   LOG_MSG("Invalid packet: not long enough");
  //   return;
  // }
  // sr_ethernet_hdr_t *curr_eth_frame=(sr_ethernet_hdr_t *)packet;
  // uint16_t eth_type = curr_eth_frame->ether_type;
  // if(eth_type==ethertype_arp)
  // {
  //   process_arp_packet(sr,(void*)(packet+sizeof(sr_ethernet_hdr_t)),len-sizeof(sr_ethernet_hdr_t));
  // }
  // else if (eth_type==ethertype_ip)
  // {
  //   process_ip_packet(sr,(void*)(packet+ sizeof(sr_ethernet_hdr_t)),len-sizeof(sr_ethernet_hdr_t));
  // }
  // else 
  //   return;

}/* end sr_ForwardPacket */

// void process_ip_packet(sr_instance  *sr,void *ip_datagram, unsigned int len)
// {
//   sr_ip_hdr *curr_ip_hdr=(sr_ip_hdr*)(ip_datagram);
//   if(cksum(curr_ip_hdr)==0) 
//     return;

// }
// uint16_t cksum()