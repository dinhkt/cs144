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
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/
void reply_arp(struct sr_instance *sr, void *arp_packet,unsigned int len,struct sr_if *);
void process_ip_packet(struct sr_instance  *sr,void *ip_packet, unsigned int len);
void process_arp_packet(struct sr_instance *sr,void *arp_packet, unsigned int len);
int correct_checksum(sr_ip_hdr_t * curr_ip_hdr);
struct sr_rt * LPM_lookup(struct sr_instance * sr, uint32_t ip_dest);
void send_arp_request(struct sr_instance* sr,struct sr_if *if_to_send, uint32_t ip_dest);
void forward_packet(struct sr_if *if_to_send, void* ip_packet,struct sr_arpentry *match_arpcache);
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
  print_hdrs(packet,len);
  /* fill in code here */
  if(len<sizeof(sr_ethernet_hdr_t))
  {
    printf("Invalid packet: not long enough");
    return;
  }
  sr_ethernet_hdr_t *curr_eth_frame=(sr_ethernet_hdr_t *)packet;
  uint16_t eth_type = ntohs(curr_eth_frame->ether_type);
  if(eth_type==ethertype_arp)
  {
    printf("receive arp");
    process_arp_packet(sr,(void*)packet,len);
  }
  else if (eth_type==ethertype_ip)
  {
    printf("receive ip packet");
    process_ip_packet(sr,(void*)packet,len);
  }
  else 
    return;

}/* end sr_ForwardPacket */
void process_ip_packet(struct sr_instance  *sr,void *ip_packet, unsigned int len)
{
  sr_ip_hdr_t *curr_ip_hdr =(sr_ip_hdr_t *)(ip_packet+sizeof(sr_ethernet_hdr_t));
  if (correct_checksum(curr_ip_hdr))
  {
    uint32_t ip_dest=curr_ip_hdr->ip_dst;
    /*look up entry by longest prefix match*/
    struct sr_rt * chosen_entry=LPM_lookup(sr,ip_dest);
    printf("\n%s\n",chosen_entry->interface);
    struct sr_if * if_to_send=sr->if_list;
    while(if_to_send!=NULL)
    {
      if (strcmp(if_to_send->name,chosen_entry->interface)==0)
        break;
      if_to_send=if_to_send->next;
    }
    /*decrease TTL by 1 */
    curr_ip_hdr->ip_ttl-=1;
    /*lookup in arp cache*/
    struct sr_arpentry *match_arpcache=sr_arpcache_lookup(&sr->cache,ip_dest);
    if(match_arpcache ==NULL)
      send_arp_request(sr,if_to_send,ip_dest);
    else 
      forward_packet(if_to_send,ip_packet,match_arpcache);
  }
  else
    printf("corrupt\n");
  return;
}
void process_arp_packet(struct sr_instance *sr,void *arp_packet, unsigned int len)
{
  sr_arp_hdr_t *curr_arp_hdr = (sr_arp_hdr_t *)(arp_packet+sizeof(sr_ethernet_hdr_t));
  if(curr_arp_hdr->ar_op==1)
  {
    struct sr_if *if_frame_come_from = sr->if_list;
    while(if_frame_come_from!=NULL)
    {
    /*printf("%d\n",curr_arp_hdr->ar_tip);
    /sr_print_if(if_frame_come_from);*/
      if ( curr_arp_hdr->ar_tip == if_frame_come_from->ip)
      {
        reply_arp(sr,arp_packet,len,if_frame_come_from);
        break;
      }
      if_frame_come_from=if_frame_come_from->next;
    }
  /*free(curr_arp_hdr);
  free(if_frame_come_from);*/
    return;
  }
  else
  {
    sr_arpcache_insert(&sr->cache,curr_arp_hdr->ar_sha,curr_arp_hdr->ar_sip);
    sr_arpcache_dump(&sr->cache);
  }
}
void send_arp_request(struct sr_instance* sr,struct sr_if *if_to_send, uint32_t ip_dest)
{
  void *arp_frame_to_send=malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));
  sr_ethernet_hdr_t *eth_header_to_send=(sr_ethernet_hdr_t *) malloc(sizeof(sr_ethernet_hdr_t));
  memset((void*)eth_header_to_send,0,sizeof(sr_ethernet_hdr_t));
  sr_arp_hdr_t *arp_header_to_send=(sr_arp_hdr_t *)malloc(sizeof(sr_arp_hdr_t));
  memset((void*)arp_header_to_send,0,sizeof(sr_arp_hdr_t));
  void *ff_mac=malloc(ETHER_ADDR_LEN);
  memset(ff_mac,0xff,ETHER_ADDR_LEN);
  /*set fields of arp request*/
  memcpy((void*)(eth_header_to_send->ether_dhost),ff_mac,ETHER_ADDR_LEN);
  memcpy((void*)(eth_header_to_send->ether_shost) , (void *)(if_to_send->addr),ETHER_ADDR_LEN);
  eth_header_to_send->ether_type=htons(0x0806);

  arp_header_to_send->ar_hrd=htons(1);
  arp_header_to_send->ar_pro=htons(2048);
  arp_header_to_send->ar_hln=6;
  arp_header_to_send->ar_pln=4;
  arp_header_to_send->ar_op=htons(1);
  /*set mac and ip of source and dest arp header*/
  
  memcpy((void *)(arp_header_to_send->ar_sha),(void *)(if_to_send->addr),ETHER_ADDR_LEN);
  arp_header_to_send->ar_sip = if_to_send->ip;

  memset(ff_mac,0,ETHER_ADDR_LEN);
  memcpy((void*)(arp_header_to_send->ar_tha),ff_mac,ETHER_ADDR_LEN);
  arp_header_to_send->ar_tip=ip_dest;

  memcpy(arp_frame_to_send,(void *)eth_header_to_send,sizeof(sr_ethernet_hdr_t));
  memcpy(arp_frame_to_send+sizeof(sr_ethernet_hdr_t),(void *)arp_header_to_send,sizeof(sr_arp_hdr_t));
  print_hdrs(arp_frame_to_send,sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));

  int ret_val= sr_send_packet(sr,(uint8_t *)arp_frame_to_send,98,if_to_send->name);
  if(ret_val<0)
    fprintf(stderr, "Failed to send\n");
}
void reply_arp(struct sr_instance *sr, void *arp_packet,unsigned int len,struct sr_if *curr_sr_if)
{
  void *arp_frame_to_send=malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));
  sr_ethernet_hdr_t *eth_header_to_send=(sr_ethernet_hdr_t *) malloc(sizeof(sr_ethernet_hdr_t));
  memset((void*)eth_header_to_send,0,sizeof(sr_ethernet_hdr_t));
  sr_arp_hdr_t *arp_header_to_send=(sr_arp_hdr_t *)malloc(sizeof(sr_arp_hdr_t));
  memset((void*)arp_header_to_send,0,sizeof(sr_arp_hdr_t));
  

  /* set fields of ethernet header*/
  memcpy((void*)(eth_header_to_send->ether_dhost) , (void *)(((sr_ethernet_hdr_t *)arp_packet)->ether_shost),ETHER_ADDR_LEN);
  memcpy((void*)(eth_header_to_send->ether_shost) , (void *)(curr_sr_if->addr),ETHER_ADDR_LEN);
  eth_header_to_send->ether_type=((sr_ethernet_hdr_t *)arp_packet)->ether_type;
  /*set opcode = 2 as reply arp*/
  arp_header_to_send->ar_hrd=((sr_arp_hdr_t *)(arp_packet+sizeof(sr_ethernet_hdr_t)))->ar_hrd;
  arp_header_to_send->ar_pro=((sr_arp_hdr_t *)(arp_packet+sizeof(sr_ethernet_hdr_t)))->ar_pro;
  arp_header_to_send->ar_hln=((sr_arp_hdr_t *)(arp_packet+sizeof(sr_ethernet_hdr_t)))->ar_hln;
  arp_header_to_send->ar_pln=((sr_arp_hdr_t *)(arp_packet+sizeof(sr_ethernet_hdr_t)))->ar_pln;
  arp_header_to_send->ar_op=htons(2);
  /*set mac and ip of source and dest arp header*/
  
  memcpy((void *)(arp_header_to_send->ar_sha),(void *)(curr_sr_if->addr),ETHER_ADDR_LEN);
  arp_header_to_send->ar_sip = curr_sr_if->ip;

  memcpy((void *)(arp_header_to_send->ar_tha),(void *)(((sr_ethernet_hdr_t *)arp_packet)->ether_shost),ETHER_ADDR_LEN);
  arp_header_to_send->ar_tip=((sr_arp_hdr_t *)(arp_packet+sizeof(sr_ethernet_hdr_t)))->ar_sip;

  memcpy(arp_frame_to_send,(void *)eth_header_to_send,sizeof(sr_ethernet_hdr_t));
  memcpy(arp_frame_to_send+sizeof(sr_ethernet_hdr_t),(void *)arp_header_to_send,sizeof(sr_arp_hdr_t));
  print_hdrs(arp_frame_to_send,sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));

  int ret_val= sr_send_packet(sr,(uint8_t *)arp_frame_to_send,len,curr_sr_if->name);
  if(ret_val<0)
    fprintf(stderr, "Failed to send\n");
} 
int correct_checksum(sr_ip_hdr_t * curr_ip_hdr)
{
  uint16_t *arr=malloc(sizeof(sr_ip_hdr_t));
  memcpy(arr,curr_ip_hdr,sizeof(sr_ip_hdr_t));
  int i;
  uint32_t compute_sum=0;
  for (i=0;i<10;i++)
  {
    compute_sum+=ntohs(arr[i]);
  }
  uint16_t carry=compute_sum>>16;
  if ((uint16_t)compute_sum+carry==0xffff) 
    return 1;
  return 0;
}
struct sr_rt * LPM_lookup(struct sr_instance * sr, uint32_t ip_dest)
{
  struct sr_rt *chosen_entry = sr->routing_table;
  uint32_t xor_val,num;
  struct sr_rt *curr_entry = sr->routing_table;
  num=ip_dest ^ sr->routing_table->dest.s_addr;
  while(curr_entry!= NULL)
  {
    xor_val=ip_dest ^ curr_entry->dest.s_addr;
    if(xor_val<num)
    {
      num=xor_val;
      chosen_entry=curr_entry;
    }
    curr_entry=curr_entry->next;
  }
  return chosen_entry;
}
void forward_packet(struct sr_if *if_to_send, void* ip_packet,struct sr_arpentry *match_arpcache)
{
  printf("checked\n");
  
}