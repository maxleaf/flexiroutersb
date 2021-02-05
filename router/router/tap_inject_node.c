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
 *   - add support in fragmented packets designated for TAP
 *   - fix b->current to enable packets received on L2GRE to be pushed into TAP
 *   - enable VxLan decapsulation before packets are pushed into TAP
 */

#include "tap_inject.h"

#include <netinet/in.h>
#include <vlib/vlib.h>
#ifdef FLEXIWAN_FIX
#include <sys/uio.h>
#endif /* FLEXIWAN_FIX */
#include <vnet/ethernet/arp_packet.h>

vlib_node_registration_t tap_inject_rx_node;
vlib_node_registration_t tap_inject_tx_node;
vlib_node_registration_t tap_inject_neighbor_node;

enum {
  NEXT_NEIGHBOR_ARP,
  NEXT_NEIGHBOR_ICMP6,
};

typedef enum
{
  TAP_INJECT_INPUT_IP4_LOOKUP,
  TAP_INJECT_INPUT_IP6_LOOKUP,
  TAP_INJECT_INPUT_N_NEXT,
} tap_inject_input_t;


/**
 * @brief Dynamically added tap_inject DPO type
 */
dpo_type_t tap_inject_dpo_type;

#ifdef FLEXIWAN_FIX
static inline void
tap_inject_tap_send_buffer (vlib_main_t * vm, int fd, vlib_buffer_t * b)
{
  struct iovec iov;
  ssize_t n_bytes;
  u8 *    reassembled_buffer = 0;

  iov.iov_base = vlib_buffer_get_current (b);
  iov.iov_len = b->current_length;

  // Handle fragmented packet:
  // Calculate total lenght, allocate buffer and copy all fragments into it.
  // TODO: use static buffer per thread.
  /* Handle fragmented packet */
  if (b->flags & VLIB_BUFFER_NEXT_PRESENT)
  {
    u16             total_length = 0;
    vlib_buffer_t * b_curr = b;
    u8 *            p_buff;

    while (b_curr->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      total_length += b_curr->current_length;
      b_curr = vlib_get_buffer (vm, b_curr->next_buffer);
    }
    total_length += b_curr->current_length;

    reassembled_buffer = clib_mem_alloc (total_length);
    if (reassembled_buffer == 0)
    {
      clib_warning ("clib_mem_alloc (total_length=%d)failed", total_length);
      return;
    }

    b_curr = b;
    p_buff = reassembled_buffer;
    while (p_buff < (reassembled_buffer + total_length))
    {
      clib_memcpy_fast(p_buff, b_curr->data + b_curr->current_data, b_curr->current_length);
      p_buff += b_curr->current_length;
      b_curr = vlib_get_buffer (vm, b_curr->next_buffer);
    }

    iov.iov_base = reassembled_buffer;
    iov.iov_len  = total_length;
  }

  n_bytes = writev (fd, &iov, 1);

  if (n_bytes < 0)
    clib_warning ("writev failed");
  // Handle fragmented packet
  //else if (n_bytes < b->current_length || b->flags & VLIB_BUFFER_NEXT_PRESENT)
  else if (n_bytes < b->current_length)
    clib_warning ("buffer truncated");

  if (reassembled_buffer)
    clib_mem_free(reassembled_buffer);
}
#else
static inline void
tap_inject_tap_send_buffer (int fd, vlib_buffer_t * b)
{
  struct iovec iov;
  ssize_t n_bytes;

  iov.iov_base = vlib_buffer_get_current (b);
  iov.iov_len = b->current_length;

  n_bytes = writev (fd, &iov, 1);

  if (n_bytes < 0)
    clib_warning ("writev failed");
  else if (n_bytes < b->current_length || b->flags & VLIB_BUFFER_NEXT_PRESENT)
    clib_warning ("buffer truncated");
}
#endif /* FLEXIWAN_FIX */

static uword
tap_inject_tx (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * f)
{
  vlib_buffer_t * b;
  u32 * pkts;
  u32 fd;
  u32 i;

  pkts = vlib_frame_vector_args (f);

  for (i = 0; i < f->n_vectors; ++i)
    {
      b = vlib_get_buffer (vm, pkts[i]);

      fd = tap_inject_lookup_tap_fd (vnet_buffer (b)->sw_if_index[VLIB_RX]);
      if (fd == ~0)
        continue;

      /* Re-wind the buffer to the start of the Ethernet header. */
#ifdef FLEXIWAN_FIX
      // The '-b->current_data' assumes that packet is regular L2-L3-APP packet.
      // This is not true in case of l2gre.
      // The packet that comes out of L2-GRE Tunnel (ipsec-gre node)
      // has L2-IPSEC_ESP-L2-L3-APP structure
      // vlib_buffer_advance (b, -b->current_data);
      vlib_buffer_advance (b, -sizeof(ethernet_header_t));

      tap_inject_tap_send_buffer (vm, fd, b);
#endif /* FLEXIWAN_FIX */
    }

  vlib_buffer_free (vm, pkts, f->n_vectors);
  return f->n_vectors;
}

VLIB_REGISTER_NODE (tap_inject_tx_node) = {
  .function = tap_inject_tx,
  .name = "tap-inject-tx",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
};

#ifdef FLEXIWAN_FIX
VLIB_NODE_FUNCTION_MULTIARCH (tap_inject_tx_node,
                              tap_inject_tx);

VNET_FEATURE_INIT (tap_inject_tx_node, static) = {
  .arc_name = "ip4-punt",
  .node_name = "tap-inject-tx",
  .runs_before = VNET_FEATURES("error-punt"),
};

VLIB_REGISTER_NODE (ip6_tap_inject_tx_node) = {
  .function = tap_inject_tx,
  .name = "ip6-tap-inject-tx",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
};

VLIB_NODE_FUNCTION_MULTIARCH (ip6_tap_inject_tx_node,
                              tap_inject_tx);

VNET_FEATURE_INIT (ip6_tap_inject_tx_node, static) = {
  .arc_name = "ip6-punt",
  .node_name = "ip6-tap-inject-tx",
  .runs_before = VNET_FEATURES("error-punt"),
};
#endif /* FLEXIWAN_FIX */

static uword
tap_inject_neighbor (vlib_main_t * vm,
                     vlib_node_runtime_t * node, vlib_frame_t * f)
{
  vlib_buffer_t * b;
  u32 * pkts;
  u32 fd;
  u32 i;
  u32 bi;
  u32 next_index = node->cached_next_index;
  u32 next = ~0;
  u32 n_left;
  u32 * to_next;

  pkts = vlib_frame_vector_args (f);

  for (i = 0; i < f->n_vectors; ++i)
    {
      bi = pkts[i];
      b = vlib_get_buffer (vm, bi);

      fd = tap_inject_lookup_tap_fd (vnet_buffer (b)->sw_if_index[VLIB_RX]);
      if (fd == ~0)
        {
          vlib_buffer_free (vm, &bi, 1);
          continue;
        }

      /* Re-wind the buffer to the start of the Ethernet header. */
#ifdef FLEXIWAN_FIX
      // The '-b->current_data' assumes that packet is regular L2-L3-APP packet.
      // This is not true in case of l2gre.
      // The packet that comes out of L2-GRE Tunnel (ipsec-gre node)
      // has L2-IPSEC_ESP-L2-L3-APP structure
      // vlib_buffer_advance (b, -b->current_data);
      vlib_buffer_advance (b, -sizeof(ethernet_header_t));

      tap_inject_tap_send_buffer (vm, fd, b);
#endif /* FLEXIWAN_FIX */
      /* Send the buffer to a neighbor node too? */
      {
        ethernet_header_t * eth = vlib_buffer_get_current (b);
        u16 ether_type = htons (eth->type);

        if (ether_type == ETHERNET_TYPE_ARP)
          {
            ethernet_arp_header_t * arp = (void *)(eth + 1);

            if (arp->opcode == ntohs (ETHERNET_ARP_OPCODE_reply))
              next = NEXT_NEIGHBOR_ARP;
          }
        else if (ether_type == ETHERNET_TYPE_IP6)
          {
            ip6_header_t * ip = (void *)(eth + 1);
            icmp46_header_t * icmp = (void *)(ip + 1);

            if (ip->protocol == IP_PROTOCOL_ICMP6 &&
                icmp->type == ICMP6_neighbor_advertisement)
              next = NEXT_NEIGHBOR_ICMP6;
          }
      }

      if (next == ~0)
        {
          vlib_buffer_free (vm, &bi, 1);
          continue;
        }

      /* ARP and ICMP6 expect to start processing after the Ethernet header. */
      vlib_buffer_advance (b, sizeof (ethernet_header_t));

      vlib_get_next_frame (vm, node, next_index, to_next, n_left);

      *(to_next++) = bi;
      --n_left;

      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                       n_left, bi, next);
      vlib_put_next_frame (vm, node, next_index, n_left);
    }

  return f->n_vectors;
}

VLIB_REGISTER_NODE (tap_inject_neighbor_node) = {
  .function = tap_inject_neighbor,
  .name = "tap-inject-neighbor",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = 2,
  .next_nodes = {
    [NEXT_NEIGHBOR_ARP] = "arp-input",
    [NEXT_NEIGHBOR_ICMP6] = "icmp6-neighbor-solicitation",
  },
};


#define MTU 1500
#define MTU_BUFFERS ((MTU + VLIB_BUFFER_DATA_SIZE - 1) / VLIB_BUFFER_DATA_SIZE)
#define NUM_BUFFERS_TO_ALLOC 32

static inline u32
tap_rx_get_next_node(u32 ether_type)
{
  if (ether_type == ETHERNET_TYPE_IP4)
    return TAP_INJECT_INPUT_IP4_LOOKUP;
  else if (ether_type == ETHERNET_TYPE_IP6)
    return TAP_INJECT_INPUT_IP6_LOOKUP;
  else
    return TAP_INJECT_INPUT_N_NEXT;
}

static inline u32
tap_rx_ip4_get_worker_offset (ip4_header_t * ip4)
{
  tap_inject_main_t *tm = tap_inject_get_main();
  u32 hash;

  hash = ip4->src_address.as_u32 + (ip4->src_address.as_u32 >> 8) +
    (ip4->src_address.as_u32 >> 16) + (ip4->src_address.as_u32 >> 24);

  if (PREDICT_TRUE (is_pow2 (tm->num_workers)))
    return hash & (tm->num_workers - 1);
  else
    return hash % tm->num_workers;
}

static inline u32
tap_rx_ip6_get_worker_offset (ip6_header_t * ip6)
{
  tap_inject_main_t *tm = tap_inject_get_main();
  u32 hash;
  ip6_address_t *addr = &ip6->src_address;

#ifdef clib_crc32c_uses_intrinsics
  hash = clib_crc32c ((u8 *) addr->as_u32, 16);
#else
  u64 tmp = addr->as_u64[0] ^ addr->as_u64[1];
  hash = clib_xxhash (tmp);
#endif

  if (PREDICT_TRUE (is_pow2 (tm->num_workers)))
    return hash & (tm->num_workers - 1);
  else
    return hash % tm->num_workers;
}

static inline void
tap_rx_process_via_ip_path ( vlib_main_t* vm, vlib_node_runtime_t * node, 
			    vnet_hw_interface_t *hw, u32 bi0, u32 next_index)
{
  tap_inject_main_t * im = tap_inject_get_main ();
  vlib_buffer_t *b = vlib_get_buffer (vm, bi0);
  // ip-lookup uses it in fib index calculation
  vnet_buffer (b)->sw_if_index[VLIB_TX] = ~0;
  vlib_buffer_advance (b, sizeof (ethernet_header_t));

  if (next_index == TAP_INJECT_INPUT_IP4_LOOKUP)
    {
      ip4_header_t *ip4 = vlib_buffer_get_current (b);
      if (im->num_workers)
	{
	  u16 ip4_ti = im->first_worker_index + tap_rx_ip4_get_worker_offset(ip4);
	  vlib_buffer_enqueue_to_thread (vm, im->ip4_handoff_queue_index,
					 &bi0, &ip4_ti, 1, 1);
	}
      else
	{
	  u32 * ip4_next;
	  u32 n_left_to_ip4_next;
	  vlib_get_next_frame (vm, node, TAP_INJECT_INPUT_IP4_LOOKUP,
			       ip4_next, n_left_to_ip4_next);
	  ip4_next[0] = bi0;
	  n_left_to_ip4_next--;
	  vlib_put_next_frame (vm, node, TAP_INJECT_INPUT_IP4_LOOKUP,
			       n_left_to_ip4_next);
	}
    }
  else if (next_index == TAP_INJECT_INPUT_IP6_LOOKUP)
    {
      ip6_header_t *ip6 = vlib_buffer_get_current (b);
      if (im->num_workers)
	{
	  u16 ip6_ti = im->first_worker_index + tap_rx_ip6_get_worker_offset(ip6);
	  vlib_buffer_enqueue_to_thread (vm, im->ip6_handoff_queue_index,
					 &bi0, &ip6_ti, 1, 1);
	}
      else
	{
	  u32 * ip6_next;
	  u32 n_left_to_ip6_next;
	  vlib_get_next_frame (vm, node, TAP_INJECT_INPUT_IP6_LOOKUP,
			       ip6_next, n_left_to_ip6_next);
	  ip6_next[0] = bi0;
	  n_left_to_ip6_next--;
	  vlib_put_next_frame (vm, node, TAP_INJECT_INPUT_IP6_LOOKUP,
			       n_left_to_ip6_next);
	}
    }
  else
    {
      clib_error ("tap_inject - Invalid next index");
      vlib_buffer_free (vm, &bi0, 1);
    }
}

static inline uword
tap_rx (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * f, int fd)
{
  tap_inject_main_t * im = tap_inject_get_main ();
  u32 sw_if_index;
  struct iovec iov[MTU_BUFFERS];
  u32 bi[MTU_BUFFERS];
  vlib_buffer_t * b;
  ssize_t n_bytes;
  ssize_t n_bytes_left;
  u32 i, j;

  sw_if_index = tap_inject_lookup_sw_if_index_from_tap_fd (fd);
  if (sw_if_index == ~0)
    return 0;

  /* Allocate buffers in bulk when there are less than enough to rx an MTU. */
  if (vec_len (im->rx_buffers) < MTU_BUFFERS)
    {
      u32 len = vec_len (im->rx_buffers);

      len = vlib_buffer_alloc_from_free_list (vm,
                    &im->rx_buffers[len], NUM_BUFFERS_TO_ALLOC,
                    VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);

      _vec_len (im->rx_buffers) += len;

      if (vec_len (im->rx_buffers) < MTU_BUFFERS)
        {
          clib_warning ("failed to allocate buffers");
          return 0;
        }
    }

  /* Fill buffers from the end of the list to make it easier to resize. */
  for (i = 0, j = vec_len (im->rx_buffers) - 1; i < MTU_BUFFERS; ++i, --j)
    {
      vlib_buffer_t * b;

      bi[i] = im->rx_buffers[j];

      b = vlib_get_buffer (vm, bi[i]);

      iov[i].iov_base = b->data;
      iov[i].iov_len = VLIB_BUFFER_DATA_SIZE;
    }

  n_bytes = readv (fd, iov, MTU_BUFFERS);
  if (n_bytes < 0)
    {
      clib_warning ("readv failed");
      return 0;
    }

  b = vlib_get_buffer (vm, bi[0]);

  vnet_buffer (b)->sw_if_index[VLIB_RX] = sw_if_index;
  vnet_buffer (b)->sw_if_index[VLIB_TX] = sw_if_index;

  n_bytes_left = n_bytes - VLIB_BUFFER_DATA_SIZE;

  if (n_bytes_left > 0)
    {
      b->total_length_not_including_first_buffer = n_bytes_left;
      b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
    }

  b->current_length = n_bytes;

  /* If necessary, configure any remaining buffers in the chain. */
  for (i = 1; n_bytes_left > 0; ++i, n_bytes_left -= VLIB_BUFFER_DATA_SIZE)
    {
      b = vlib_get_buffer (vm, bi[i - 1]);
      b->current_length = VLIB_BUFFER_DATA_SIZE;
      b->flags |= VLIB_BUFFER_NEXT_PRESENT;
      b->next_buffer = bi[i];

      b = vlib_get_buffer (vm, bi[i]);
      b->current_length = n_bytes_left;
    }

  _vec_len (im->rx_buffers) -= i;

  /* Get the packet to the output node. */
  {
    vnet_hw_interface_t * hw;

    hw = vnet_get_hw_interface (vnet_get_main (), sw_if_index);
    ethernet_header_t *eh = vlib_buffer_get_current (b);
    u32 next_index = tap_rx_get_next_node(clib_net_to_host_u16 (eh->type));

    if ((vnet_interface_check_if_loopback (hw) == 0) ||
	(next_index == TAP_INJECT_INPUT_N_NEXT))
      {
	// If loopback interface or non IP - Pass on to output node write 
	vlib_frame_t * new_frame;
	u32 * to_next;
	new_frame = vlib_get_frame_to_node (vm, hw->output_node_index);
	to_next = vlib_frame_vector_args (new_frame);
	to_next[0] = bi[0];
	new_frame->n_vectors = 1;

	vlib_put_frame_to_node (vm, hw->output_node_index, new_frame);
      }
    else
      {
	// Process via IP path - Pass via interface output features like NAT, ACL
	tap_rx_process_via_ip_path (vm, node, hw, bi[0], next_index);
      }
  }

  return 1;
}

static uword
tap_inject_rx (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * f)
{
  tap_inject_main_t * im = tap_inject_get_main ();
  u32 * fd;
  uword count = 0;

  vec_foreach (fd, im->rx_file_descriptors)
    {
      if (tap_rx (vm, node, f, *fd) != 1)
        {
          clib_warning ("rx failed");
          count = 0;
          break;
        }
      ++count;
    }

  vec_free (im->rx_file_descriptors);

  return count;
}

VLIB_REGISTER_NODE (tap_inject_rx_node) = {
  .function = tap_inject_rx,
  .name = "tap-inject-rx",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .vector_size = sizeof (u32),
  .n_next_nodes = TAP_INJECT_INPUT_N_NEXT,
  .next_nodes = {
      [TAP_INJECT_INPUT_IP4_LOOKUP] = "ip4-lookup",
      [TAP_INJECT_INPUT_IP6_LOOKUP] = "ip6-lookup",
  },
};

/**
 * @brief no-op lock function.
 */
static void
tap_inject_dpo_lock (dpo_id_t * dpo)
{
}

/**
 * @brief no-op unlock function.
 */
static void
tap_inject_dpo_unlock (dpo_id_t * dpo)
{
}

u8 *
format_tap_inject_dpo (u8 * s, va_list * args)
{
  return (format (s, "tap-inject:[%d]", 0));
}

const static dpo_vft_t tap_inject_vft = {
  .dv_lock = tap_inject_dpo_lock,
  .dv_unlock = tap_inject_dpo_unlock,
  .dv_format = format_tap_inject_dpo,
};

const static char *const tap_inject_tx_nodes[] = {
  "tap-inject-tx",
  NULL,
};

const static char *const *const tap_inject_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = tap_inject_tx_nodes,
  [DPO_PROTO_IP6] = tap_inject_tx_nodes,
};

static clib_error_t *
tap_inject_init (vlib_main_t * vm)
{
  tap_inject_main_t * im = tap_inject_get_main ();

  im->rx_node_index = tap_inject_rx_node.index;
  im->tx_node_index = tap_inject_tx_node.index;
  im->neighbor_node_index = tap_inject_neighbor_node.index;

  tap_inject_dpo_type = dpo_register_new_type (&tap_inject_vft, tap_inject_nodes);

  vec_alloc (im->rx_buffers, NUM_BUFFERS_TO_ALLOC);
  vec_reset_length (im->rx_buffers);

  // Setup queues for IP lookup handoffs
  vlib_node_t *node = vlib_get_node_by_name (vm, (u8 *) "ip4-lookup");
  im->ip4_handoff_queue_index = vlib_frame_queue_main_init (node->index, 0);
  node = vlib_get_node_by_name (vm, (u8 *) "ip6-lookup");
  im->ip6_handoff_queue_index = vlib_frame_queue_main_init (node->index, 0);

  // Init num worker threads - Used in handoff queue assignment
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  uword *threads = hash_get_mem (tm->thread_registrations_by_name, "workers");
  if (threads)
    {
      vlib_thread_registration_t *worker;
      worker = (vlib_thread_registration_t *) threads[0];
      if (worker)
        {
	  im->first_worker_index = worker->first_index;
          im->num_workers = worker->count;
        }
    }

  return 0;
}

VLIB_INIT_FUNCTION (tap_inject_init);
