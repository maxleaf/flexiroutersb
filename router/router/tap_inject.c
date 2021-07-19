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
 *   - enable VxLan decapsulation before packets are pushed into TAP
 *   - hide internally used loopback interfaces from TAP/Linux
 *
 *  List of features made for FlexiWAN (denoted by FLEXIWAN_FEATURE flag):
 *   - nat-tap-inject-output: Support to NAT packets received from tap
 *   interface before being put on wire
 */

#include "tap_inject.h"

#include <vnet/mfib/mfib_table.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/lookup.h>
#include <vnet/fib/fib.h>
#include <vnet/osi/osi.h>
#include <vnet/gre/gre.h>

#ifdef FLEXIWAN_FIX
#include <vnet/udp/udp.h>
#endif

static tap_inject_main_t tap_inject_main;
extern dpo_type_t tap_inject_dpo_type;

tap_inject_main_t *
tap_inject_get_main (void)
{
  return &tap_inject_main;
}

void
tap_inject_insert_tap (u32 sw_if_index, u32 tap_fd, u32 tap_if_index)
{
  tap_inject_main_t * im = tap_inject_get_main ();

  vec_validate_init_empty (im->sw_if_index_to_tap_fd, sw_if_index, ~0);
  vec_validate_init_empty (im->sw_if_index_to_tap_if_index, sw_if_index, ~0);
#ifdef FLEXIWAN_FEATURE /* nat-tap-inject-output */
  vec_validate_init_empty (im->sw_if_index_to_ip4_output, sw_if_index, ~0);
#endif /* FLEXIWAN_FEATURE */

  vec_validate_init_empty (im->tap_fd_to_sw_if_index, tap_fd, ~0);

  im->sw_if_index_to_tap_fd[sw_if_index] = tap_fd;
  im->sw_if_index_to_tap_if_index[sw_if_index] = tap_if_index;

  im->tap_fd_to_sw_if_index[tap_fd] = sw_if_index;

  hash_set (im->tap_if_index_to_sw_if_index, tap_if_index, sw_if_index);
}

void
tap_inject_delete_tap (u32 sw_if_index)
{
  tap_inject_main_t * im = tap_inject_get_main ();
  u32 tap_fd = im->sw_if_index_to_tap_fd[sw_if_index];
  u32 tap_if_index = im->sw_if_index_to_tap_if_index[sw_if_index];

  im->sw_if_index_to_tap_if_index[sw_if_index] = ~0;
  im->sw_if_index_to_tap_fd[sw_if_index] = ~0;
#ifdef FLEXIWAN_FEATURE /* nat-tap-inject-output */
  im->sw_if_index_to_ip4_output[sw_if_index] = ~0;
#endif /* FLEXIWAN_FEATURE */

  im->tap_fd_to_sw_if_index[tap_fd] = ~0;

  hash_unset (im->tap_if_index_to_sw_if_index, tap_if_index);
}

u32
tap_inject_lookup_tap_fd (u32 sw_if_index)
{
  tap_inject_main_t * im = tap_inject_get_main ();

  vec_validate_init_empty (im->sw_if_index_to_tap_fd, sw_if_index, ~0);
  return im->sw_if_index_to_tap_fd[sw_if_index];
}

u32
tap_inject_lookup_sw_if_index_from_tap_fd (u32 tap_fd)
{
  tap_inject_main_t * im = tap_inject_get_main ();

  vec_validate_init_empty (im->tap_fd_to_sw_if_index, tap_fd, ~0);
  return im->tap_fd_to_sw_if_index[tap_fd];
}

u32
tap_inject_lookup_sw_if_index_from_tap_if_index (u32 tap_if_index)
{
  tap_inject_main_t * im = tap_inject_get_main ();
  uword * sw_if_index;

  sw_if_index = hash_get (im->tap_if_index_to_sw_if_index, tap_if_index);
  return sw_if_index ? *(u32 *)sw_if_index : ~0;
}

#ifdef FLEXIWAN_FEATURE /* nat-tap-inject-output */
u32
tap_inject_lookup_ip4_output_from_sw_if_index (u32 sw_if_index)
{
  tap_inject_main_t * im = tap_inject_get_main ();
  return im->sw_if_index_to_ip4_output[sw_if_index];
}

void
tap_inject_set_ip4_output (u32 sw_if_index, u32 enable)
{
  tap_inject_main_t * im = tap_inject_get_main ();
  im->sw_if_index_to_ip4_output[sw_if_index] = enable;
}
#endif /* FLEXIWAN_FEATURE */


/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    // .version = VPP_BUILD_VER, FIXME
    .description = "router",
};
/* *INDENT-ON* */


static void
tap_inject_disable (void)
{
  tap_inject_main_t * im = tap_inject_get_main ();

  im->flags &= ~TAP_INJECT_F_ENABLED;

  clib_warning ("tap-inject is not actually disabled.");
}

static clib_error_t *
tap_inject_enable (void)
{
  vlib_main_t * vm = vlib_get_main ();
  tap_inject_main_t * im = tap_inject_get_main ();

  if (tap_inject_is_enabled ())
    return 0;

  tap_inject_enable_netlink ();

  /* Only enable netlink? */
  if (im->flags & TAP_INJECT_F_CONFIG_NETLINK)
    {
      im->flags |= TAP_INJECT_F_ENABLED;
      return 0;
    }

  /* Register ARP and ICMP6 as neighbor nodes. */
  ethernet_register_input_type (vm, ETHERNET_TYPE_ARP, im->neighbor_node_index);
  ip6_register_protocol (IP_PROTOCOL_ICMP6, im->neighbor_node_index);

  /* Register remaining protocols. */
  ip4_register_protocol (IP_PROTOCOL_ICMP, im->tx_node_index);

  ip4_register_protocol (IP_PROTOCOL_OSPF, im->tx_node_index);
  ip4_register_protocol (IP_PROTOCOL_TCP, im->tx_node_index);
#ifdef FLEXIWAN_FIX
  // Issue: all UDP traffic is captured by tap-inject before VxLan node intercepts it.
  //        as a result VxLAN tunnel that sits on BVI bridge with TAP interface does not work.
  // Solution: comment out tap-inject registration on UDP traffic. This allows traffic to reach
  //           VxLAN node. UDP traffic designated for TAP will reach udp-local node and will be dropped.
  //           To avoid drop and to pass it to tap-inject, the punt feature is used.
  //           Punt arc is used to redirect traffic that was supposed to be dropped into various nodes
  //           that are registered Punt feature. Registration is performed by adding tap-inject into
  //           ip4-punt arc.
  udp_punt_unknown(vm, 1, 1);
  vnet_feature_enable_disable ("ip4-punt", "tap-inject-tx", 0, 1, 0, 0);
#else
  ip4_register_protocol (IP_PROTOCOL_UDP, im->tx_node_index);
#endif /* FLEXIWAN_FIX */

  ip6_register_protocol (IP_PROTOCOL_OSPF, im->tx_node_index);
  ip6_register_protocol (IP_PROTOCOL_TCP, im->tx_node_index);
#ifdef FLEXIWAN_FIX
  udp_punt_unknown(vm, 0, 1);
  vnet_feature_enable_disable ("ip6-punt", "ip6-tap-inject-tx", 0, 1, 0, 0);
#else
  ip6_register_protocol (IP_PROTOCOL_UDP, im->tx_node_index);
#endif /* FLEXIWAN_FIX */
  /* Registering ISIS to OSI node. */
  osi_register_input_protocol (OSI_PROTOCOL_isis, im->tx_node_index);

  {
    dpo_id_t dpo = DPO_INVALID;

    const mfib_prefix_t pfx_224_0_0_0 = {
        .fp_len = 24,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_grp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0xe0000000),
        },
        .fp_src_addr = {
            .ip4.as_u32 = 0,
        },
    };

    dpo_set(&dpo, tap_inject_dpo_type, DPO_PROTO_IP4, ~0);

    index_t repi = replicate_create(1, DPO_PROTO_IP4);
    replicate_set_bucket(repi, 0, &dpo);

    mfib_table_entry_special_add(0,
                                 &pfx_224_0_0_0,
                                 MFIB_SOURCE_API,
                                 MFIB_ENTRY_FLAG_ACCEPT_ALL_ITF,
                                 repi);

    dpo_reset(&dpo);
  }

  im->flags |= TAP_INJECT_F_ENABLED;

  return 0;
}

static uword
tap_inject_iface_isr (vlib_main_t * vm, vlib_node_runtime_t * node,
                      vlib_frame_t * f)
{
  tap_inject_main_t * im = tap_inject_get_main ();
  vnet_hw_interface_t * hw;
  u32 * hw_if_index;
  clib_error_t * err = 0;

  vec_foreach (hw_if_index, im->interfaces_to_enable)
    {
      hw = vnet_get_hw_interface (vnet_get_main (), *hw_if_index);

      if (hw->hw_class_index == ethernet_hw_interface_class.index)
        {
#ifdef FLEXIWAN_FIX
          if (hw->dev_class_index == gre_device_class.index)
            {
              continue;
            }
#endif /* FLEXIWAN_FIX */

          err = tap_inject_tap_connect (hw);
          if (err)
            break;
        }
    }

  vec_foreach (hw_if_index, im->interfaces_to_disable)
    tap_inject_tap_disconnect (*hw_if_index);

  vec_free (im->interfaces_to_enable);
  vec_free (im->interfaces_to_disable);

  return err ? -1 : 0;
}

VLIB_REGISTER_NODE (tap_inject_iface_isr_node, static) = {
  .function = tap_inject_iface_isr,
  .name = "tap-inject-iface-isr",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .vector_size = sizeof (u32),
};


static clib_error_t *
tap_inject_interface_add_del (struct vnet_main_t * vnet_main, u32 hw_if_index,
                              u32 add)
{
  vlib_main_t * vm = vlib_get_main ();
  tap_inject_main_t * im = tap_inject_get_main ();

  if (!tap_inject_is_config_enabled ())
    return 0;

  tap_inject_enable ();

#ifdef FLEXIWAN_FIX
  // As of Dec-2019 we use loop0-bridge-l2gre_ipsec_tunnel and loop1-bridge-vxlan_tunnel 
  // in order to enable NAT 1:1. The loop1 interface should not be exposed to Linux/user,
  // as it is for internal use only, and no ping/netplan etc should be enabled.
  // Therefore we hide it from user by escaping it in this function.
  // The fwagent enforces odd instance numbers for loop1 interfaces,
  // e.g. loop5, loop7, loop9 etc, and even indexes for loop0 interfaces.
  // See usage of create_loopback_instance() function in fwagent.
  {
      vnet_hw_interface_t * hw = vnet_get_hw_interface (vnet_main, hw_if_index);
      if (hw->name != NULL  &&  clib_memcmp(hw->name, "loop", 4) == 0  &&
          hw->dev_instance % 2 == 1)
        return 0;
  }
#endif /* FLEXIWAN_FIX */

  if (add)
    vec_add1 (im->interfaces_to_enable, hw_if_index);
  else
    vec_add1 (im->interfaces_to_disable, hw_if_index);

  vlib_node_set_interrupt_pending (vm, tap_inject_iface_isr_node.index);

  return 0;
}

VNET_HW_INTERFACE_ADD_DEL_FUNCTION (tap_inject_interface_add_del);


static clib_error_t *
tap_inject_enable_disable_all_interfaces (int enable)
{
  vnet_main_t * vnet_main = vnet_get_main ();
  tap_inject_main_t * im = tap_inject_get_main ();
  vnet_hw_interface_t * interfaces;
  vnet_hw_interface_t * hw;
  u32 ** indices;

  if (enable)
    tap_inject_enable ();
  else
    tap_inject_disable ();

  /* Collect all the interface indices. */
  interfaces = vnet_main->interface_main.hw_interfaces;
  indices = enable ? &im->interfaces_to_enable : &im->interfaces_to_disable;
  pool_foreach (hw, interfaces) {vec_add1 (*indices, hw - interfaces);};

  if (tap_inject_iface_isr (vlib_get_main (), 0, 0))
    return clib_error_return (0, "tap-inject interface add del isr failed");

  return 0;
}

static clib_error_t *
tap_inject_cli (vlib_main_t * vm, unformat_input_t * input,
                 vlib_cli_command_t * cmd)
{
  tap_inject_main_t * im = tap_inject_get_main ();

  if (cmd->function_arg)
    {
      clib_error_t * err;

      if (tap_inject_is_config_disabled ())
        return clib_error_return (0,
            "tap-inject is disabled in config, thus cannot be enabled.");

      /* Enable */
      err = tap_inject_enable_disable_all_interfaces (1);
      if (err)
        {
          tap_inject_enable_disable_all_interfaces (0);
          return err;
        }

      im->flags |= TAP_INJECT_F_CONFIG_ENABLE;
    }
  else
    {
      /* Disable */
      tap_inject_enable_disable_all_interfaces (0);
      im->flags &= ~TAP_INJECT_F_CONFIG_ENABLE;
    }

  return 0;
}

VLIB_CLI_COMMAND (tap_inject_enable_cmd, static) = {
  .path = "enable tap-inject",
  .short_help = "enable tap-inject",
  .function = tap_inject_cli,
  .function_arg = 1,
};

VLIB_CLI_COMMAND (tap_inject_disable_cmd, static) = {
  .path = "disable tap-inject",
  .short_help = "disable tap-inject",
  .function = tap_inject_cli,
  .function_arg = 0,
};


static clib_error_t *
show_tap_inject (vlib_main_t * vm, unformat_input_t * input,
                 vlib_cli_command_t * cmd)
{
  vnet_main_t * vnet_main = vnet_get_main ();
  tap_inject_main_t * im = tap_inject_get_main ();
  u32 k, v;

  if (tap_inject_is_config_disabled ())
    {
      vlib_cli_output (vm, "tap-inject is disabled in config.\n");
      return 0;
    }

  if (!tap_inject_is_enabled ())
    {
      vlib_cli_output (vm, "tap-inject is not enabled.\n");
      return 0;
    }

  hash_foreach (k, v, im->tap_if_index_to_sw_if_index, {
    vlib_cli_output (vm, "%U -> %U",
            format_vnet_sw_interface_name, vnet_main,
            vnet_get_sw_interface (vnet_main, v),
            format_tap_inject_tap_name, k);
  });

  return 0;
}

VLIB_CLI_COMMAND (show_tap_inject_cmd, static) = {
  .path = "show tap-inject",
  .short_help = "show tap-inject",
  .function = show_tap_inject,
};


#ifdef FLEXIWAN_FEATURE /* nat-tap-inject-output */
static clib_error_t *
tap_inject_enable_ip4_output_cli (vlib_main_t * vm, unformat_input_t * input,
			   vlib_cli_command_t * cmd)
{
  tap_inject_main_t * im = tap_inject_get_main ();
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  i32 is_del = 0;
  clib_error_t *error = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface,
		    vnet_get_main(), &sw_if_index))
	;
      else if (unformat (line_input, "del"))
	is_del = 1;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (sw_if_index == ~0)
    {
      error = clib_error_return (0, "Invalid sw_if_index");
      goto done;
    }
  if (tap_inject_lookup_tap_fd(sw_if_index) == ~0)
    {
      error = clib_error_return (0, "The input is not a tap interface ");
      goto done;
    }
  if (is_del)
    {
      tap_inject_set_ip4_output (sw_if_index, ~0);
    }
  else
    {
      if (im->ip4_output_tap_node_index != ~0)
	{
	  if (im->ip4_output_tap_queue_index == ~0)
	    {
	      im->ip4_output_tap_queue_index =
		vlib_frame_queue_main_init (im->ip4_output_tap_node_index, 0);
	    }
	  tap_inject_set_ip4_output (sw_if_index, 1);
	}
      else
	{
	  error = clib_error_return (0, "ip4-output-tap-inject feature not found");
	}
    }

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (tap_inject_ip4_output_cli, static) = {
  .path = "tap-inject enable-ip4-output interface",
  .short_help = "tap-inject enable-ip4-output interface <interface> [del]",
  .function = tap_inject_enable_ip4_output_cli,
};
#endif /* FLEXIWAN_FEATURE */


static clib_error_t *
tap_inject_config (vlib_main_t * vm, unformat_input_t * input)
{
  tap_inject_main_t * im = tap_inject_get_main ();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable"))
        im->flags |= TAP_INJECT_F_CONFIG_ENABLE;

      else if (unformat (input, "disable"))
        im->flags |= TAP_INJECT_F_CONFIG_DISABLE;

      else if (unformat (input, "netlink-only"))
        im->flags |= TAP_INJECT_F_CONFIG_NETLINK;

      else
        return clib_error_return (0, "syntax error `%U'",
                                  format_unformat_error, input);
    }

  if (tap_inject_is_config_enabled () && tap_inject_is_config_disabled ())
    return clib_error_return (0,
              "tap-inject cannot be both enabled and disabled.");

  return 0;
}

VLIB_CONFIG_FUNCTION (tap_inject_config, "tap-inject");
