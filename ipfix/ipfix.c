/*
 * Copyright (c) 2017 Igalia
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * @file
 * @brief IPFIX Plugin, plugin API / trace / CLI handling.
 */

#include <vnet/ip/ip4_packet.h>
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <ipfix/ipfix.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vppinfra/random.h>

/* define message IDs */
#include <ipfix/ipfix_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <ipfix/ipfix_all_api_h.h> 
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <ipfix/ipfix_all_api_h.h> 
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <ipfix/ipfix_all_api_h.h> 
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <ipfix/ipfix_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE sm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* List of message types that this plugin understands */

#define foreach_ipfix_plugin_api_msg                           \
_(IPFIX_FLOW_METER_ENABLE_DISABLE, ipfix_flow_meter_enable_disable)

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = IPFIX_PLUGIN_BUILD_VER,
    .description = "Ipfix of VPP Plugin",
};
/* *INDENT-ON* */

/**
 * @brief Enable/disable the flow_meter plugin.
 *
 * Action function shared between message handler and debug CLI.
 */

int ipfix_flow_meter_enable_disable (ipfix_main_t * sm, u32 sw_if_index,
                                   int enable_disable)
{
  vnet_sw_interface_t * sw;
  int rv = 0;

  /* Utterly wrong? */
  if (pool_is_free_index (sm->vnet_main->interface_main.sw_interfaces, 
                          sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (sm->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;
  
  vnet_feature_enable_disable ("ip4-output", "ipfix-meter-ip4",
                               sw_if_index, enable_disable, 0, 0);
  vnet_feature_enable_disable ("ip6-output", "ipfix-meter-ip6",
                               sw_if_index, enable_disable, 0, 0);

  return rv;
}

static clib_error_t *
flow_meter_enable_disable_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  ipfix_main_t * sm = &ipfix_main;
  u32 sw_if_index = ~0;
  int enable_disable = 1;
    
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "disable"))
      enable_disable = 0;
    else if (unformat (input, "%U", unformat_vnet_sw_interface,
                       sm->vnet_main, &sw_if_index))
      ;
    else
      break;
  }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");
    
  rv = ipfix_flow_meter_enable_disable (sm, sw_if_index, enable_disable);

  switch(rv) {
  case 0:
    break;

  case VNET_API_ERROR_INVALID_SW_IF_INDEX:
    return clib_error_return 
      (0, "Invalid interface, only works on physical ports");
    break;

  case VNET_API_ERROR_UNIMPLEMENTED:
    return clib_error_return (0, "Device driver doesn't support redirection");
    break;

  default:
    return clib_error_return (0, "ipfix_flow_meter_enable_disable returned %d",
                              rv);
  }
  return 0;
}

static clib_error_t * ipfix_set_command_fn (vlib_main_t * vm,
                                            unformat_input_t * input,
                                            vlib_cli_command_t * cmd)
{
  u32 val = 0;
  ip4_address_t addr;
  ipfix_main_t * im = &ipfix_main;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(input, "timeout")) {
      if (unformat(input, "idle %u", &val)) {
        im->idle_flow_timeout = val * 1e3;
      } else if (unformat(input, "active %u", &val)) {
        im->active_flow_timeout = val * 1e3;
      } else if (unformat(input, "template %u", &val)) {
        im->template_timeout = val * 1e3;
      } else {
        return clib_error_return(0,
                                 "expected timeout command, got `%U`",
                                 format_unformat_error, input);
      }
    } else if (unformat(input, "port")) {
      if (unformat(input, "exporter %u", &val)) {
        if (val > 65536) {
          return clib_error_return(0, "expected valid port");
        }
        im->exporter_port = val;
      } else if (unformat(input, "collector %u")) {
        if (val > 65536) {
          return clib_error_return(0, "expected valid port");
        }
        im->collector_port = val;
      } else {
        return clib_error_return(0,
                                 "expected port command, got `%U`",
                                 format_unformat_error, input);
      }
    } else if (unformat(input, "ip")) {
      if (unformat(input, "exporter %U", unformat_ip4_address, &addr)) {
        im->exporter_ip = addr;
      } else if (unformat(input, "collector %U", unformat_ip4_address, &addr)) {
        im->collector_ip = addr;
      } else {
        return clib_error_return(0,
                                 "expected port command, got `%U`",
                                 format_unformat_error, input);
      }
    } else if (unformat(input, "observation-domain %u", &val)) {
      im->observation_domain = val;
    } else {
      return clib_error_return(0, "unknown command");
    }
  }

  return 0;
}

/**
 * @brief CLI command to enable/disable the ipfix plugin.
 */
VLIB_CLI_COMMAND (ipfix_enable_command, static) = {
  .path = "ipfix flow-meter",
  .short_help = "ipfix flow-meter <interface-name> [disable]",
  .function = flow_meter_enable_disable_command_fn,
};

/**
 * @brief CLI command to set options for the ipfix plugin.
 */
VLIB_CLI_COMMAND (ipfix_set_command, static) = {
  .path = "set ipfix",
  .short_help = "set ipfix [timeout {idle|active|template} <seconds>] [{port|ip} {collector|exporter} <value>] [observation-domain <num>]",
  .function = ipfix_set_command_fn,
};

/**
 * @brief Plugin API message handler.
 */
static void vl_api_ipfix_flow_meter_enable_disable_t_handler
(vl_api_ipfix_flow_meter_enable_disable_t * mp)
{
  vl_api_ipfix_flow_meter_enable_disable_reply_t * rmp;
  ipfix_main_t * sm = &ipfix_main;
  int rv;

  rv = ipfix_flow_meter_enable_disable (sm, ntohl(mp->sw_if_index),
                                        (int) (mp->enable_disable));
  
  REPLY_MACRO(VL_API_IPFIX_FLOW_METER_ENABLE_DISABLE_REPLY);
}

/**
 * @brief Set up the API message handling tables.
 */
static clib_error_t *
ipfix_plugin_api_hookup (vlib_main_t *vm)
{
  ipfix_main_t * sm = &ipfix_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                           #n,                                  \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1); 
    foreach_ipfix_plugin_api_msg;
#undef _

    return 0;
}

#define vl_msg_name_crc_list
#include <ipfix/ipfix_all_api_h.h>
#undef vl_msg_name_crc_list

static void 
setup_message_id_table (ipfix_main_t * sm, api_main_t *am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + sm->msg_id_base);
  foreach_vl_msg_name_crc_ipfix;
#undef _
}

/* TODO: Replace with the user configurable template.
 * Parsed from the CSV file describing the fields
 */
static void ipfix_make_v10_template(netflow_v10_template_t *template,
                                    u8 is_ipv6)
{
  /* Initialize an empty flow key to calculate the offsets against. */
  ipfix_ip4_flow_value_t record_ip4;
  ipfix_ip6_flow_value_t record_ip6;

  /* Initialize the set vector. */
  template->sets = 0;

  /* Create a single set for these */
  netflow_v10_template_set_t set;
  /* Data record sets start from #256 */
  set.id = 256 + is_ipv6;
  set.fields = 0; // Initialize the fields vector.

  netflow_v10_field_specifier_t src_address;
  netflow_v10_field_specifier_t dst_address;
  netflow_v10_field_specifier_t protocol;
  netflow_v10_field_specifier_t src_port;
  netflow_v10_field_specifier_t dst_port;
  netflow_v10_field_specifier_t flow_start;
  netflow_v10_field_specifier_t flow_end;
  netflow_v10_field_specifier_t octet_count;
  netflow_v10_field_specifier_t packet_count;

  if (is_ipv6) {
    src_address.identifier = sourceIPv6Address;
    src_address.size = sizeof(u8) * 16;

    dst_address.identifier = destinationIPv6Address;
    dst_address.size = sizeof(u8) * 16;

    src_address.record_offset = (size_t)&record_ip6.flow_key.src - (size_t)&record_ip6;
    dst_address.record_offset = (size_t)&record_ip6.flow_key.dst - (size_t)&record_ip6;
    protocol.record_offset = (size_t)&record_ip6.flow_key.protocol - (size_t)&record_ip6;
    src_port.record_offset = (size_t)&record_ip6.flow_key.src_port - (size_t)&record_ip6;
    dst_port.record_offset = (size_t)&record_ip6.flow_key.dst_port - (size_t)&record_ip6;
    flow_start.record_offset = (size_t)&record_ip6.flow_start - (size_t)&record_ip6;
    flow_end.record_offset = (size_t)&record_ip6.flow_end - (size_t)&record_ip6;
    octet_count.record_offset = (size_t)&record_ip6.octet_delta_count - (size_t)&record_ip6;
    packet_count.record_offset = (size_t)&record_ip6.packet_delta_count - (size_t)&record_ip6;
  } else {
    src_address.identifier = sourceIPv4Address;
    src_address.size = sizeof(u8) * 4;

    dst_address.identifier = destinationIPv4Address;
    dst_address.size = sizeof(u8) * 4;

    src_address.record_offset = (size_t)&record_ip4.flow_key.src - (size_t)&record_ip4;
    dst_address.record_offset = (size_t)&record_ip4.flow_key.dst - (size_t)&record_ip4;
    protocol.record_offset = (size_t)&record_ip4.flow_key.protocol - (size_t)&record_ip4;
    src_port.record_offset = (size_t)&record_ip4.flow_key.src_port - (size_t)&record_ip4;
    dst_port.record_offset = (size_t)&record_ip4.flow_key.dst_port - (size_t)&record_ip4;
    flow_start.record_offset = (size_t)&record_ip4.flow_start - (size_t)&record_ip4;
    flow_end.record_offset = (size_t)&record_ip4.flow_end - (size_t)&record_ip4;
    octet_count.record_offset = (size_t)&record_ip4.octet_delta_count - (size_t)&record_ip4;
    packet_count.record_offset = (size_t)&record_ip4.packet_delta_count - (size_t)&record_ip4;
  }

  protocol.identifier = protocolIdentifier;
  protocol.size = sizeof(u8);

  src_port.identifier = sourceTransportPort;
  src_port.size = sizeof(u16);

  dst_port.identifier = destinationTransportPort;
  dst_port.size = sizeof(u16);

  flow_start.identifier = flowStartMilliseconds;
  flow_start.size = sizeof(u64);

  flow_end.identifier = flowEndMilliseconds;
  flow_end.size = sizeof(u64);

  octet_count.identifier = octetDeltaCount;
  octet_count.size = sizeof(u64);

  packet_count.identifier = packetDeltaCount;
  packet_count.size = sizeof(u64);

  vec_add1(set.fields, src_address);
  vec_add1(set.fields, dst_address);
  vec_add1(set.fields, protocol);
  vec_add1(set.fields, src_port);
  vec_add1(set.fields, dst_port);
  vec_add1(set.fields, flow_start);
  vec_add1(set.fields, flow_end);
  vec_add1(set.fields, octet_count);
  vec_add1(set.fields, packet_count);

  vec_add1(template->sets, set);
}

/**
 * @brief Initialize the ipfix plugin.
 */
static clib_error_t * ipfix_init (vlib_main_t * vm)
{
  ipfix_main_t * sm = &ipfix_main;
  clib_error_t * error = 0;
  u8 * name;
  u32 rand_port;

  sm->vnet_main =  vnet_get_main ();

  name = format (0, "ipfix_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  sm->msg_id_base = vl_msg_api_get_msg_ids 
      ((char *) name, VL_MSG_FIRST_AVAILABLE);

  /* store this node's vlib_main in the ipfix_main_t */
  sm->vlib_main = vm;

  /* Create random port between 49152 to 0xFFFF */
  sm->random_seed = random_default_seed();
  rand_port = (random_u32(&sm->random_seed) % (0xFFFF - 49152)) + 49152;

  /* Initialize configuration values */
  sm->exporter_port = rand_port;
  sm->collector_port = 4739;
  sm->collector_ip.data[0] = 10;
  sm->collector_ip.data[1] = 10;
  sm->collector_ip.data[2] = 1;
  sm->collector_ip.data[3] = 1;
  sm->exporter_ip.data[0] = 10;
  sm->exporter_ip.data[1] = 10;
  sm->exporter_ip.data[2] = 1;
  sm->exporter_ip.data[3] = 2;
  sm->observation_domain = 256;
  sm->idle_flow_timeout = 300 * 1e3;
  sm->active_flow_timeout = 120 * 1e3;
  sm->template_timeout = 600 * 1e3;

  /* Initialize templates */
  /* FIXME: do we need to free these at some point? */
  sm->template_ip4 = clib_mem_alloc(sizeof(netflow_v10_template_t));
  sm->template_ip6 = clib_mem_alloc(sizeof(netflow_v10_template_t));
  ipfix_make_v10_template(sm->template_ip4, 0);
  ipfix_make_v10_template(sm->template_ip6, 1);

  /* Initialize flow records vector */
  sm->flow_records_ip4 = 0;
  sm->flow_records_ip6 = 0;

  /* Initialize expired flow records vector */
  sm->expired_records_ip4 = 0;
  sm->expired_records_ip6 = 0;

  /* Initialize IPFIX data packets vector */
  sm->data_packets = 0;

  clib_bihash_init_16_8(&sm->flow_hash_ip4, "flowhash", 1048, 128<<20);
  clib_bihash_init_48_8(&sm->flow_hash_ip6, "flowhash", 1048, 128<<20);

  error = ipfix_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (sm, &api_main);

  vec_free(name);

  return error;
}

VLIB_INIT_FUNCTION (ipfix_init);

/**
 * @brief Hook the ipfix plugins into the VPP graph hierarchy.
 */
VNET_FEATURE_INIT (ipfix_meter_ip4, static) =
{
  .arc_name = "ip4-output",
  .node_name = "ipfix-meter-ip4",
  .runs_before = VNET_FEATURES ("interface-output"),
};

VNET_FEATURE_INIT (ipfix_meter_ip6, static) =
{
  .arc_name = "ip6-output",
  .node_name = "ipfix-meter-ip6",
  .runs_before = VNET_FEATURES ("interface-output"),
};
