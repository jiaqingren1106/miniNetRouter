#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sr_arpcache.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_rt.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr) {
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

int longest_prefix_match(struct sr_instance *sr, uint32_t ip_dst,
                         struct sr_rt **match_entry) {
  int net_reachable = 0;
  struct sr_rt *rt_walker = sr->routing_table;
  uint32_t cur_longest_mask = 0;
  while (rt_walker) {
    uint32_t ip_prefix = ip_dst & rt_walker->mask.s_addr;
    if ((rt_walker->dest.s_addr & rt_walker->mask.s_addr) == ip_prefix) {
      net_reachable = 1;
      if (rt_walker->mask.s_addr > cur_longest_mask) {
        *match_entry = rt_walker;
        cur_longest_mask = rt_walker->mask.s_addr;
      }
    }
    rt_walker = rt_walker->next;
  }
  return net_reachable;
}

/* Helper for sr_handlepacket() to send type 3 ICMP messages. */
void send_icmp_msg(struct sr_instance *sr, uint8_t *packet, char *interface,
                       uint8_t type, uint8_t code) {

  struct sr_if *incoming_iface = sr_get_interface(sr, interface);
  sr_ethernet_hdr_t *original_ethernet_header = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)&packet[sizeof(sr_ethernet_hdr_t)];

  unsigned int net_unreachable_reply_sz = sizeof(sr_ethernet_hdr_t) +
                                          sizeof(sr_ip_hdr_t) +
                                          sizeof(sr_icmp_t3_hdr_t);
  uint8_t net_unreachable_reply[net_unreachable_reply_sz];
  memcpy(net_unreachable_reply, packet,
         sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  sr_ethernet_hdr_t *net_unreachable_ethernet =
      (sr_ethernet_hdr_t *)net_unreachable_reply;
  sr_ip_hdr_t *net_unreachable_ip =
      (sr_ip_hdr_t *)(net_unreachable_reply + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t *net_unreachable_icmp =
      (sr_icmp_t3_hdr_t *)(net_unreachable_reply + sizeof(sr_ethernet_hdr_t) +
                           sizeof(sr_ip_hdr_t));

  memcpy(net_unreachable_ethernet->ether_dhost,
         original_ethernet_header->ether_shost, ETHER_ADDR_LEN);
  memcpy(net_unreachable_ethernet->ether_shost, incoming_iface->addr,
         ETHER_ADDR_LEN);
  net_unreachable_icmp->icmp_type = type;
  net_unreachable_icmp->icmp_code = code;
  net_unreachable_icmp->unused = 0;
  net_unreachable_icmp->icmp_sum = 0;
  memcpy(net_unreachable_icmp->data, packet + sizeof(sr_ethernet_hdr_t),
         sizeof(sr_ip_hdr_t) + 8);
  net_unreachable_icmp->icmp_sum =
      cksum(net_unreachable_icmp, sizeof(sr_icmp_t3_hdr_t));
  if (type == 3 && code == 3) {
    net_unreachable_ip->ip_src = ip_header->ip_dst;
  } else {
    net_unreachable_ip->ip_src = incoming_iface->ip;
  }
  net_unreachable_ip->ip_dst = ip_header->ip_src;
  net_unreachable_ip->ip_p = ip_protocol_icmp;
  net_unreachable_ip->ip_len =
      htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  net_unreachable_ip->ip_ttl = 64;
  net_unreachable_ip->ip_sum = 0;
  net_unreachable_ip->ip_sum = cksum(net_unreachable_ip, sizeof(sr_ip_hdr_t));

  printf("\n\n=================Headers to send==================\n\n");
  print_hdr_eth(net_unreachable_ethernet);
  print_hdr_ip(net_unreachable_ip);
  printf("\n\nSupposed IP len: %d\n\n",
         sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  print_hdr_icmp(net_unreachable_icmp);

  /* TODO: Handle error of send_packet */
  int ret = sr_send_packet(sr, net_unreachable_reply, net_unreachable_reply_sz,
                           interface);
  printf("sr_send_packet ret: %d\n", ret);
}

void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req) {

  struct sr_rt *match_entry;
  longest_prefix_match(sr, req->ip, &match_entry);
  char *fwd_interface = match_entry->interface;
  struct sr_if *forward_iface = sr_get_interface(sr, fwd_interface);
  time_t now;
  time(&now);
  printf("\n\n time diff %f\n\n", difftime(now, req->sent));
  if (difftime(now, req->sent) >= 1.0) {
    /*TODO > or >= 5*/
    if (req->times_sent >= 5) {
      /* ICMP host unreachable */
      /*send all packets on the req->packets linked list*/
      struct sr_packet *pkt_walker = req->packets;
      while (pkt_walker) {
        /*TODO: check which iface to use*/
        sr_ip_hdr_t *pkt_src_ip =
            (sr_ip_hdr_t *)(pkt_walker->buf + sizeof(sr_ethernet_hdr_t));
        struct sr_rt *pkt_src_entry;
        longest_prefix_match(sr, pkt_src_ip->ip_src, &pkt_src_entry);
        send_icmp_msg(sr, pkt_walker->buf, pkt_src_entry->interface, 3, 1);
        pkt_walker = pkt_walker->next;
      }
      sr_arpreq_destroy(&(sr->cache), req);
    } else {
      /*send ARP req*/
      unsigned int arp_request_sz =
          sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
      uint8_t arp_request[arp_request_sz];
      sr_ethernet_hdr_t *arp_request_ethernet =
          (sr_ethernet_hdr_t *)arp_request;
      sr_arp_hdr_t *arp_request_header =
          (sr_arp_hdr_t *)(arp_request + sizeof(sr_ethernet_hdr_t));
      memset(arp_request_ethernet->ether_dhost, 255, ETHER_ADDR_LEN);
      memcpy(arp_request_ethernet->ether_shost, forward_iface->addr,
             ETHER_ADDR_LEN);
      arp_request_ethernet->ether_type = htons(ethertype_arp);
      arp_request_header->ar_hrd = htons(arp_hrd_ethernet);
      arp_request_header->ar_pro = htons(ethertype_ip);
      arp_request_header->ar_hln = ETHER_ADDR_LEN;
      arp_request_header->ar_pln = 4;
      arp_request_header->ar_op = htons(arp_op_request);
      memcpy(arp_request_header->ar_sha, forward_iface->addr, ETHER_ADDR_LEN);
      memset(arp_request_header->ar_tha, 255, ETHER_ADDR_LEN);
      arp_request_header->ar_sip = forward_iface->ip;
      arp_request_header->ar_tip = req->ip;
      print_hdr_eth(arp_request_ethernet);
      print_hdr_arp(arp_request_header);
      int ret = sr_send_packet(sr, arp_request, arp_request_sz, fwd_interface);
      printf("\n\nsr_send_pkt ret: %d\n\n", ret);
      req->sent = now;
      req->times_sent++;
    }
  }
}

void forward_ip_packet(struct sr_instance *sr, uint8_t *packet,
                       unsigned int len, uint32_t ip_dst, char *fwd_iface) {
  struct sr_if *forward_iface = sr_get_interface(sr, fwd_iface);
  sr_ethernet_hdr_t *forward_ethernet = (sr_ethernet_hdr_t *)packet;

  /* check ARP cache */
  struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), ip_dst);
  if (entry) {
    printf("\n\n====== ARP cache hit ========\n\n");
    memcpy(forward_ethernet->ether_dhost, entry->mac, ETHER_ADDR_LEN);
    memcpy(forward_ethernet->ether_shost, forward_iface->addr, ETHER_ADDR_LEN);
    free(entry);
    int ret = sr_send_packet(sr, packet, len, fwd_iface);
    printf("sr_send_packet ret: %d\n", ret);
  } else {
    printf("\n\n============= miss !! ===========\n\n");
    struct sr_arpreq *req =
        sr_arpcache_queuereq(&(sr->cache), ip_dst, packet, len, fwd_iface);
    handle_arpreq(sr, req);
  }
}

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

void sr_handlepacket(struct sr_instance *sr, uint8_t *packet /* lent */,
                     unsigned int len, char *interface /* lent */) {
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);

  /* fill in code here */
  sr_ethernet_hdr_t *original_ethernet_header = (sr_ethernet_hdr_t *)packet;
  printf("----original eth header-------");
  print_hdr_eth(original_ethernet_header);
  sr_ethernet_hdr_t next_hop_ethernet;
  struct sr_if *incoming_iface = sr_get_interface(sr, interface);

  if (ethertype(packet) == ethertype_arp) {
    printf("\n\n\n\nReceived ARP packet; type: %x\n\n\n", ethertype(packet));
    /* Receive ARP packet */
    sr_arp_hdr_t *incoming_arp =
        (sr_arp_hdr_t *)&packet[sizeof(sr_ethernet_hdr_t)];

    int for_me = 0;
    struct sr_if *if_walker = sr->if_list;
    while (if_walker) {
      if (if_walker->ip == incoming_arp->ar_tip) {
        for_me = 1;
        break;
      }
      if_walker = if_walker->next;
    }

    if (for_me) {

      uint16_t arp_op = ntohs(incoming_arp->ar_op);
      printf("\n\n\nARP op: %x\n\n", arp_op);
      if (arp_op == arp_op_request) {
        printf("\n\nGet an ARP request\n\n");
        printf("\n\n Request for one of router's interfaces\n\n");
        /* Construct ARP reply and send it back */
        memcpy(next_hop_ethernet.ether_dhost,
               original_ethernet_header->ether_shost, ETHER_ADDR_LEN);
        memcpy(next_hop_ethernet.ether_shost, incoming_iface->addr,
               ETHER_ADDR_LEN);
        next_hop_ethernet.ether_type = htons(ethertype_arp);

        sr_arp_hdr_t arp_reply_hdr;
        memcpy(&arp_reply_hdr, incoming_arp, sizeof(sr_arp_hdr_t));
        arp_reply_hdr.ar_op = htons(arp_op_reply);
        arp_reply_hdr.ar_sip = incoming_iface->ip;
        memcpy(arp_reply_hdr.ar_sha, incoming_iface->addr, ETHER_ADDR_LEN);
        arp_reply_hdr.ar_tip = incoming_arp->ar_sip;
        memcpy(arp_reply_hdr.ar_tha, incoming_arp->ar_sha, ETHER_ADDR_LEN);

        unsigned int reply_arp_size =
            sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
        uint8_t reply_arp_packet[reply_arp_size];
        memcpy(reply_arp_packet, &next_hop_ethernet, sizeof(next_hop_ethernet));
        memcpy(reply_arp_packet + sizeof(sr_ethernet_hdr_t), &arp_reply_hdr,
               sizeof(arp_reply_hdr));

        print_hdr_eth(reply_arp_packet);
        print_hdr_arp(reply_arp_packet + sizeof(sr_ethernet_hdr_t));
        /* TODO: Handle error of send_packet */
        int ret =
            sr_send_packet(sr, reply_arp_packet, reply_arp_size, interface);
        printf("\n\n sr_send_packet ret: %d\n\n", ret);

      } else if (arp_op == arp_op_reply) {
        printf("\n\n Get an ARP reply\n\n\n");

        /* cache the IP-MAC mapping */

        struct sr_arpreq *req = sr_arpcache_insert(
            &(sr->cache), incoming_arp->ar_sha, incoming_arp->ar_sip);

        if (req) {
          /*send all packets on the req->packets linked list*/
          struct sr_packet *pkt_walker = req->packets;
          while (pkt_walker) {
            sr_ethernet_hdr_t *next_hop_eth =
                (sr_ethernet_hdr_t *)pkt_walker->buf;
            memcpy(next_hop_eth->ether_dhost, incoming_arp->ar_sha,
                   ETHER_ADDR_LEN);
            memcpy(next_hop_eth->ether_shost,
                   sr_get_interface(sr, pkt_walker->iface)->addr,
                   ETHER_ADDR_LEN);
            sr_send_packet(sr, pkt_walker->buf, pkt_walker->len,
                           pkt_walker->iface);
            pkt_walker = pkt_walker->next;
          }
          sr_arpreq_destroy(&(sr->cache), req);
        }
      }
    } else {
      ; /*TODO: ask Piazza*/
    }

  } else if (ethertype(packet) == ethertype_ip) {
    printf("\n\n\n Receive IP packet of type: %x\n\n\n", ethertype(packet));
    /* Receive IP packet */
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)&packet[sizeof(sr_ethernet_hdr_t)];

    print_hdr_ip(ip_header);
    sr_print_if_list(sr);

    /*TODO: check for incoming_iface=0 case*/
    int for_me = 0;
    struct sr_if *if_walker = sr->if_list;
    while (if_walker) {
      if (if_walker->ip == ip_header->ip_dst) {
        for_me = 1;
        break;
      }
      if_walker = if_walker->next;
    }

    if (for_me) {
      printf("\n\n\nFor me hahaha\n\n");
      if (ip_header->ip_p == ip_protocol_icmp) {

        sr_icmp_hdr_t *icmp_header =
            (sr_icmp_hdr_t *)&ip_header[sizeof(sr_ip_hdr_t)];

        /* send echo reply */
        uint8_t echo_reply[len];
        memcpy(echo_reply, packet, len);
        sr_ethernet_hdr_t *echo_ethernet = (sr_ethernet_hdr_t *)echo_reply;
        sr_ip_hdr_t *echo_ip =
            (sr_ip_hdr_t *)(echo_reply + sizeof(sr_ethernet_hdr_t));
        sr_icmp_hdr_t *echo_icmp =
            (sr_icmp_hdr_t *)(echo_reply + sizeof(sr_ethernet_hdr_t) +
                              sizeof(sr_ip_hdr_t));

        printf("\n\n=========Original headers=========\n\n");
        print_hdr_eth(echo_ethernet);
        print_hdr_ip(echo_ip);
        print_hdr_icmp(echo_icmp);

        memcpy(echo_ethernet->ether_dhost,
               original_ethernet_header->ether_shost, ETHER_ADDR_LEN);
        memcpy(echo_ethernet->ether_shost, incoming_iface->addr,
               ETHER_ADDR_LEN);
        echo_icmp->icmp_type = 0;
        echo_icmp->icmp_code = 0;
        echo_icmp->icmp_sum = 0;
        echo_icmp->icmp_sum = cksum(echo_icmp, len - sizeof(sr_ethernet_hdr_t) -
                                                   sizeof(sr_ip_hdr_t));
        echo_ip->ip_src = ip_header->ip_dst;
        echo_ip->ip_dst = ip_header->ip_src;
        echo_ip->ip_sum = 0;
        echo_ip->ip_sum = cksum(echo_ip, sizeof(sr_ip_hdr_t));

        printf("\n\n=================Headers to send==================\n\n");
        print_hdr_eth(echo_ethernet);
        print_hdr_ip(echo_ip);
        print_hdr_icmp(echo_icmp);

        /* TODO: Handle error of send_packet */
        /*int ret = sr_send_packet(sr, echo_reply, len, interface);
        printf("sr_send_packet ret: %d\n", ret);
        */
        struct sr_rt *match_entry;
        int net_reachable =
            longest_prefix_match(sr, echo_ip->ip_dst, &match_entry);
        if (net_reachable) {
          forward_ip_packet(sr, echo_reply, len, match_entry->gw.s_addr,
                            interface);
        } else {
          /*TODO: error handling maybe? ask whether this should be happening.*/
        }
      } else {
        /* TCP/UDP
           send ICMP port unreachable */
        send_icmp_msg(sr, packet, interface, 3, 3);
      }
    } else {
      /* not for me
       1. sanity check, decrement TTL, etc. (refer to asignment web) TODO: check
       whether this needs to be done before checking whether the packet is for
       me or not
         TODO: what if check sum does not match? what ICMP should be sent. ask
       Piazza */
      /*TODO: check min length and checksum */
      if ((ip_header->ip_ttl - 1) == 0 /*TTL reaches 0*/) {
        /* ICMP Time exceeded. Type 11 Code 0
         TODO: ask piazza where's type 11 ICMP */
        struct sr_rt *match_entry;
        int net_reachable =
            longest_prefix_match(sr, ip_header->ip_src, &match_entry);
        if (net_reachable) {
          send_icmp_msg(sr, packet, match_entry->interface, 11, 0);
        };
      } else {
        uint32_t ip_dst = ip_header->ip_dst;
        struct sr_rt *match_entry;
        int net_reachable = longest_prefix_match(sr, ip_dst, &match_entry);
        if (net_reachable) {
          uint8_t forward_pkt[len];
          memcpy(forward_pkt, packet, len);
          sr_ip_hdr_t *forward_ip =
              (sr_ip_hdr_t *)(forward_pkt + sizeof(sr_ethernet_hdr_t));
          forward_ip->ip_ttl -= 1;
          forward_ip->ip_sum = 0;
          forward_ip->ip_sum = cksum(forward_ip, sizeof(sr_ip_hdr_t));

          forward_ip_packet(sr, forward_pkt, len, match_entry->gw.s_addr,
                            match_entry->interface);
        } else {
          /* send ICMP net unreachable */
          send_icmp_msg(sr, packet, interface, 3, 0);
        }
      }
    }
  }

} /* end sr_ForwardPacket */
