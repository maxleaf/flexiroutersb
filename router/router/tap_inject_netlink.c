/*
 * Copyright 2016 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 *  Copyright (C) 2019 flexiWAN Ltd.
 *  List of fixes made for FlexiWAN (denoted by FLEXIWAN_FIX flag):
 *   - add missing functionality: reflect route deletion in Linux into VPP FIB
 *     (handle the RTM_DELROUTE Netlink message).
 *   - fixed deletion of ARP entries on RTM_NEWNEIGH and RTM_DELNEIGH netlink
 *     messages - see add_del_neigh() function.
 *   - fixed deletion of static ARP entries not installed by us.
 */

#include <librtnl/netns.h>
#include <vlibmemory/api.h>
#include <vnet/ip-neighbor/ip_neighbor.h>
#include <vnet/ip/lookup.h>
#include <vnet/fib/fib.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/arp/arp.h>
#include <arpa/inet.h>
#include <linux/mpls.h>
#include <vnet/mpls/packet.h>
#include <vnet/ip/ip_types_api.h>

#include "tap_inject.h"

static void
add_del_addr (ns_addr_t * a, int is_del)
{
  vlib_main_t * vm = vlib_get_main ();
  u32 sw_if_index;

  sw_if_index = tap_inject_lookup_sw_if_index_from_tap_if_index (
                                                                 a->ifaddr.ifa_index);

  if (sw_if_index == ~0)
    return;

  if (a->ifaddr.ifa_family == AF_INET)
    {
      ip4_add_del_interface_address (vm, sw_if_index,
                                     (ip4_address_t *) a->local, a->ifaddr.ifa_prefixlen, is_del);
    }
  else if (a->ifaddr.ifa_family == AF_INET6)
    {
      ip6_add_del_interface_address (vm, sw_if_index,
                                     (ip6_address_t *) a->addr, a->ifaddr.ifa_prefixlen, is_del);
    }
}


struct set_flags_args {
  u32 index;
  u8 flags;
};

static void
set_flags_cb (struct set_flags_args * a)
{
  vnet_sw_interface_set_flags (vnet_get_main (), a->index, a->flags);
}

static void
add_del_link (ns_link_t * l, int is_del)
{
  struct set_flags_args args = { ~0, 0 };
  vnet_sw_interface_t * sw;
  u8 flags = 0;
  u32 sw_if_index;

  sw_if_index = tap_inject_lookup_sw_if_index_from_tap_if_index (
                                                                 l->ifi.ifi_index);

  if (sw_if_index == ~0)
    return;

  sw = vnet_get_sw_interface (vnet_get_main (), sw_if_index);

  flags = sw->flags;

  if (l->ifi.ifi_flags & IFF_UP)
    flags |= VNET_SW_INTERFACE_FLAG_ADMIN_UP;
  else
    flags &= ~VNET_SW_INTERFACE_FLAG_ADMIN_UP;

  args.index = sw_if_index;
  args.flags = flags;

  vl_api_rpc_call_main_thread (set_flags_cb, (u8 *)&args, sizeof (args));
}


#ifdef FLEXIWAN_FIX
/* The ndm_state does NOT reflect need to add adjacency.
   Kernel can send RTM_DELNEIGH with NUD_REACHABLE state,
   as it was last state in neighbor table before removal.
   The bug causes crash in fib_path_resolve() when vppsb tries to add
   adjacency for interface that was removed (due to tunnel removal).
*/
static void
add_del_neigh (ns_neigh_t * n, int is_del)
{
  u32 sw_if_index;
  ip_address_t ip = ip_address_initializer;
  ip_address_family_t af;
  ip_neighbor_flags_t flags = IP_NEIGHBOR_FLAG_NONE;
  mac_address_t mac = ZERO_MAC_ADDRESS;

  sw_if_index = tap_inject_lookup_sw_if_index_from_tap_if_index (
                                                                 n->nd.ndm_ifindex);

  if (sw_if_index == ~0)
    return;

  flags |= IP_NEIGHBOR_FLAG_DYNAMIC;

  af = (n->nd.ndm_family == AF_INET) ? AF_IP4 : AF_IP6;
  ip_address_set (&ip, n->dst, af);
  mac_address_from_bytes (&mac, n->lladdr);

  if (n->nd.ndm_state & NUD_REACHABLE  &&  is_del==0)
    {
      ip_neighbor_add (&ip, &mac, sw_if_index,
               flags, NULL);
    }
  else if (n->nd.ndm_state & NUD_FAILED  ||  is_del==1)
    {
      if (ip_neighbor_is_dynamic_external(&ip, sw_if_index))
      {
        ip_neighbor_del (&ip, sw_if_index);
      }
    }
}

#else  /*#ifdef FLEXIWAN_FIX */

static void
add_del_neigh (ns_neigh_t * n, int is_del)
{
  vnet_main_t * vnet_main = vnet_get_main ();
  vlib_main_t * vm = vlib_get_main ();
  u32 sw_if_index;

  sw_if_index = tap_inject_lookup_sw_if_index_from_tap_if_index (
                                                                 n->nd.ndm_ifindex);

  if (sw_if_index == ~0)
    return;

  if (n->nd.ndm_family == AF_INET)
    {
      ethernet_arp_ip4_over_ethernet_address_t a;

      memset (&a, 0, sizeof (a));

      clib_memcpy (&a.ethernet, n->lladdr, ETHER_ADDR_LEN);
      clib_memcpy (&a.ip4, n->dst, sizeof (a.ip4));


      if (n->nd.ndm_state & NUD_REACHABLE)
        {
          vnet_arp_set_ip4_over_ethernet (vnet_main, sw_if_index,
                                          &a, 0 /* static */ ,
                                          0 /* no fib entry */);

        }
      else if (n->nd.ndm_state & NUD_FAILED)
        {
          vnet_arp_unset_ip4_over_ethernet (vnet_main, sw_if_index, &a);
        }
    }
  else if (n->nd.ndm_family == AF_INET6)
    {
      if (n->nd.ndm_state & NUD_REACHABLE)
        {
          vnet_set_ip6_ethernet_neighbor (vm, sw_if_index,
                                          (ip6_address_t *) n->dst, n->lladdr, ETHER_ADDR_LEN,
                                          0 /* static */,
                                          0 /* no fib entry */);
        }
      else
        vnet_unset_ip6_ethernet_neighbor (vm, sw_if_index,
                                          (ip6_address_t *) n->dst);
    }
}
#endif /*#ifdef FLEXIWAN_FIX #else*/

#define TAP_INJECT_HOST_ROUTE_TABLE_MAIN 254

static void
get_mpls_label_stack(struct mpls_label *addr, u32* l)
{
  u32 entry = ntohl(addr[0].entry);
  u32 label = (entry & MPLS_LS_LABEL_MASK) >> MPLS_LS_LABEL_SHIFT;

  for(int i = 1; label != 0; i++) {
    *l++ = label;
    if(entry & MPLS_LS_S_MASK)
      return;
    entry = ntohl(addr[i].entry);
    label = (entry & MPLS_LS_LABEL_MASK) >> MPLS_LS_LABEL_SHIFT;
  }
}

static void
add_del_fib (u32 sw_if_index, unsigned char rtm_family, unsigned char rtm_dst_len,
             u8 *dst, struct mpls_label *encap, u8 *gateway, struct rtvia *via,
             u32 priority, u32 weight, int is_del)
{
/*#warning IPv6/MPLS is disabled for now (May-2020)*/
  if (rtm_family != AF_INET)
    return;

  fib_route_path_t *rpaths = NULL;
  fib_route_path_t rpath = {};
  u32 stack[MPLS_STACK_DEPTH] = {0};
  fib_prefix_t prefix;
  u32 fib_index = ip4_fib_index_from_table_id (0);

  memset(&rpath, 0, sizeof(rpath));
  memset (&prefix, 0, sizeof (prefix));

  rpath.frp_weight = weight;
  rpath.frp_preference = priority;
  rpath.frp_sw_if_index = sw_if_index;

  if (rtm_family == AF_INET)
    {
      prefix.fp_len = rtm_dst_len;
      prefix.fp_proto = FIB_PROTOCOL_IP4;
      clib_memcpy (&prefix.fp_addr.ip4, dst, sizeof (prefix.fp_addr.ip4));
      get_mpls_label_stack(encap, stack);

      rpath.frp_proto = DPO_PROTO_IP4;
      clib_memcpy(&rpath.frp_addr.ip4, gateway, sizeof(rpath.frp_addr.ip4));

#ifdef FLEXIWAN_DEBUG
      struct sockaddr_in sa;
      char str[INET_ADDRSTRLEN];
      clib_memcpy(&sa.sin_addr.s_addr, &rpath.frp_addr.ip4, sizeof(rpath.frp_addr.ip4));
      inet_ntop(AF_INET, &(sa.sin_addr), str, INET_ADDRSTRLEN);

      struct sockaddr_in sa2;
      char dst_str[INET_ADDRSTRLEN];
      clib_memcpy(&sa2.sin_addr.s_addr, &prefix.fp_addr.ip4, sizeof(prefix.fp_addr.ip4));
      inet_ntop(AF_INET, &(sa2.sin_addr), dst_str, INET_ADDRSTRLEN);

      clib_warning("%s: %s via %s, is_del %u\n", __FUNCTION__, dst_str, str, is_del);
#endif

      /* We ignore routes that have empty gateways.
         If it is installed, it is not removed on tap interface removal.
         And such scenario leads to crash on installing a new route for
         the same network as previously deleted interface.
         Example of such issue:
         sudo ip link set dev vpp9 down
         sudo ip addr del 10.100.0.32 dev vpp9
         DBGvpp# loopback delete-interface intfc loop30
         sudo ip route add 10.100.0.32/31 via 10.100.0.29
         As a result fib_entry_src_api_path_remove() crashes due to checking
         previously deleted interface from stale route.
      */
      if (!rpath.frp_addr.ip4.as_u32) {
        return;
      }

      if(*stack != 0) {
        for(int i = 0; i < MPLS_STACK_DEPTH && stack[i] != 0; i++) {
          fib_mpls_label_t fib_label = {stack[i],0,0,0};
          vec_add1(rpath.frp_label_stack, fib_label);
        }
      }
    }
  else if (rtm_family == AF_INET6)
    {
      prefix.fp_len = rtm_dst_len;
      prefix.fp_proto = FIB_PROTOCOL_IP6;
      clib_memcpy (&prefix.fp_addr.ip6, dst, sizeof (prefix.fp_addr.ip6));

      rpath.frp_proto = DPO_PROTO_IP6;
      clib_memcpy(&rpath.frp_addr.ip6, gateway, sizeof(rpath.frp_addr.ip6));
    }
  else if (rtm_family == AF_MPLS)
    {
      u32 dst_label;
      get_mpls_label_stack((struct mpls_label*) dst, &dst_label);

      prefix.fp_len = 21;
      prefix.fp_label = dst_label;
      prefix.fp_proto = FIB_PROTOCOL_MPLS;
      prefix.fp_payload_proto = DPO_PROTO_IP4;

      clib_memcpy (&rpath.frp_addr.ip4, via->rtvia_addr, sizeof (rpath.frp_addr.ip4));

      rpath.frp_proto = DPO_PROTO_IP4;
      rpath.frp_fib_index = 0;
    }

  vec_add1(rpaths, rpath);

  if (is_del)
    {
      fib_table_entry_path_remove2(fib_index,
                                    &prefix,
                                    FIB_SOURCE_API,
                                    rpaths);
    }
  else
    {
      fib_table_entry_path_add2(fib_index,
                                &prefix,
                                FIB_SOURCE_API,
                                FIB_ENTRY_FLAG_NONE,
                                rpaths);
    }

  vec_free(rpaths);
}

static void
add_del_multipath_fib(ns_route_t * r, int is_del)
{
  u32 sw_if_index = 0;
  int attrlen = 0;
  u32 oif = 0;
  u8 gateway[16];
  u32 weight = 0;

  struct rtnexthop *nhptr = r->multipath.nhops;
  int rtnhp_len = r->multipath.length;

  while (rtnhp_len > 0)
    {
      attrlen = nhptr->rtnh_len;
      oif = nhptr->rtnh_ifindex;
      weight = nhptr->rtnh_hops + 1;

      if (attrlen == 0)
        break;

      struct rtattr *attr = RTNH_DATA(nhptr);

      if (attr->rta_type == RTA_GATEWAY) {
          memcpy(gateway, RTA_DATA(attr), RTA_PAYLOAD(attr));
        }

      sw_if_index = tap_inject_lookup_sw_if_index_from_tap_if_index (oif);
      if (sw_if_index == ~0)
        return;

      u32 new_sw_if_index = tap_inject_map_interface_get(sw_if_index);
      if (new_sw_if_index != ~0) {
        sw_if_index = new_sw_if_index;
      }

      add_del_fib(sw_if_index, r->rtm.rtm_family,
                  r->rtm.rtm_dst_len, r->dst,
                  r->encap, gateway,
                  (struct rtvia *)r->via,
                  r->priority, weight, is_del);

      rtnhp_len -= NLMSG_ALIGN(attrlen);
      nhptr = RTNH_NEXT(nhptr);
    }
}

static void
add_del_route (ns_route_t * r, int is_del)
{
  u32 sw_if_index = 0;
  u32 weight = 1;

  if (r->multipath.length > 0)
    {
      add_del_multipath_fib(r, is_del);
    }
  else
    {
      sw_if_index = tap_inject_lookup_sw_if_index_from_tap_if_index (r->oif);
      if (sw_if_index == ~0)
        return;

      u32 new_sw_if_index = tap_inject_map_interface_get(sw_if_index);
      if (new_sw_if_index != ~0) {
        sw_if_index = new_sw_if_index;
      }

      add_del_fib(sw_if_index, r->rtm.rtm_family,
                  r->rtm.rtm_dst_len, r->dst,
                  r->encap, r->gateway,
                  (struct rtvia *)r->via,
                  r->priority, weight, is_del);
    }
}

static void
netns_notify_cb (void * obj, netns_type_t type, u32 flags, uword opaque)
{
#ifdef FLEXIWAN_DEBUG
  clib_warning("%s: type %u, flags %x", __FUNCTION__, type, flags);
#endif

  if (type == NETNS_TYPE_ADDR)
    add_del_addr ((ns_addr_t *)obj, flags & NETNS_F_DEL);

  else if (type == NETNS_TYPE_LINK)
    add_del_link ((ns_link_t *)obj, flags & NETNS_F_DEL);

  else if (type == NETNS_TYPE_NEIGH)
    add_del_neigh ((ns_neigh_t *)obj, flags & NETNS_F_DEL);

  else if (type == NETNS_TYPE_ROUTE)
    add_del_route ((ns_route_t *)obj, flags & NETNS_F_DEL);
}

void
tap_inject_enable_netlink (void)
{
  char nsname = 0;
  netns_sub_t sub = {
    .notify = netns_notify_cb,
    .opaque = 0,
  };

  netns_open (&nsname, &sub);
}
