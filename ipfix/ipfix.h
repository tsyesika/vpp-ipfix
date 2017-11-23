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
#ifndef __included_ipfix_h__
#define __included_ipfix_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/bihash_48_8.h>
#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>
#include <vppinfra/vec.h>

typedef struct {
  ip4_address_t src;
  ip4_address_t dst;
  u8 protocol;
  u16 src_port;
  u16 dst_port;
} ipfix_ip4_flow_key_t;

typedef struct {
  ipfix_ip4_flow_key_t flow_key;
  u64 flow_start; //milliseconds;
  u64 flow_end; // milliseconds;
  u64 packet_delta_count;
  u64 octet_delta_count;
} ipfix_ip4_flow_value_t;

typedef struct {
    /* API message ID base */
    u16 msg_id_base;

    clib_bihash_48_8_t flow_hash;

    /* exporter configuration */
    ip4_address_t exporter_ip;
    ip4_address_t collector_ip;

    /* vector of flow records */
    ipfix_ip4_flow_value_t * flow_records;

  /* vector of expired flows to export */
  ipfix_ip4_flow_value_t * expired_records;

    /* convenience */
    vlib_main_t * vlib_main;
    vnet_main_t * vnet_main;
} ipfix_main_t;

extern ipfix_main_t ipfix_main;

extern vlib_node_registration_t ipfix_node;

#define IPFIX_PLUGIN_BUILD_VER "1.0"

#endif /* __included_ipfix_h__ */
