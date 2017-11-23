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
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <vlib/vlib.h>
#include <vnet/ip/format.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vppinfra/vec.h>
#include <vppinfra/bihash_48_8.h>
#include <ipfix/ipfix.h>


#define TCP_PROTOCOL 6
#define UDP_PROTOCOL 17

/* Amount of time between each run of the process node (in seconds) */
#define PROCESS_POLL_PERIOD 10.0

ipfix_main_t ipfix_main;

typedef struct {
  u32 next_index;
  u32 sw_if_index;
  clib_bihash_48_8_t flow_hash;
  ipfix_ip4_flow_value_t *flow_records;
} ipfix_trace_t;

static u8* format_timestamp(u8 *s, va_list *args) {
  time_t timestamp = va_arg (*args, time_t) / 1e3;
  struct tm time;

  gmtime_r(&timestamp, &time);

  s = format(s, "%04d-%02d-%02d %02d:%02d:%02d UTC",
             time.tm_year + 1900, time.tm_mon + 1, time.tm_mday,
             time.tm_hour, time.tm_min, time.tm_sec);

  return s;
}

static u8* format_ipfix_ip4_flow(u8 *s, va_list *args) {
  ipfix_ip4_flow_value_t *flow_record = va_arg (*args, ipfix_ip4_flow_value_t*);
  ipfix_ip4_flow_key_t flow_key = flow_record->flow_key;

  s = format(s, "\n[Flow key] src: %U, dst: %U, protocol: %d, src port: %U, dst port: %U\n",
             format_ip4_address, &flow_key.src,
             format_ip4_address, &flow_key.dst,
             flow_key.protocol,
             format_tcp_udp_port, flow_key.src_port,
             format_tcp_udp_port, flow_key.dst_port);
  s = format(s, "[Flow record] start: %U, end: %U, count: %d, octets: %d\n",
             format_timestamp, flow_record->flow_start,
             format_timestamp, flow_record->flow_end,
             ntohl(flow_record->packet_delta_count),
             ntohl(flow_record->octet_delta_count));

  return s;

}

/* packet trace+ format function */
static u8 * format_ipfix_trace (u8 * s, va_list * args)
{
  ipfix_ip4_flow_value_t * record;
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ipfix_trace_t * t = va_arg (*args, ipfix_trace_t *);

  s = format (s, "IPFIX: sw_if_index %d, next index %d\n",
              t->sw_if_index, t->next_index);

  vec_validate(t->flow_records, 0);
  vec_foreach(record, t->flow_records) {
    s = format (s, " %U", format_ipfix_ip4_flow, record);
  }

  s = format(s, "\n");

  return s;
}

vlib_node_registration_t ipfix_node;

#define foreach_ipfix_error \
_(SWAPPED, "Error (fixme)")

typedef enum {
#define _(sym,str) IPFIX_ERROR_##sym,
  foreach_ipfix_error
#undef _
  IPFIX_N_ERROR,
} ipfix_error_t;

static char * ipfix_error_strings[] = {
#define _(sym,string) string,
  foreach_ipfix_error
#undef _
};

typedef enum {
  IPFIX_NEXT_INTERFACE_OUTPUT,
  IPFIX_N_NEXT,
} ipfix_next_t;

static void insert_packet_flow_hash(clib_bihash_kv_48_8_t *keyvalue) {
  ipfix_main_t * im = &ipfix_main;
  clib_bihash_add_del_48_8(&im->flow_hash, keyvalue, 1);
}

static void create_flow_key(ipfix_ip4_flow_key_t *flow_key, ip4_header_t *packet) {
  flow_key->src = packet->src_address;
  flow_key->dst = packet->dst_address;
  flow_key->protocol = packet->protocol;

  switch (packet->protocol) {
    udp_header_t *udp;
    tcp_header_t *tcp;
  case UDP_PROTOCOL:
    udp = ip4_next_header(packet);
    flow_key->src_port = udp->src_port;
    flow_key->dst_port = udp->dst_port;
    break;
  case TCP_PROTOCOL:
    tcp = ip4_next_header(packet);
    flow_key->src_port = tcp->src_port;
    flow_key->dst_port = tcp->dst_port;
    break;
  default:
    flow_key->src_port = 0;
    flow_key->dst_port = 0;
  }
}

static void process_packet(ip4_header_t *packet) {
  ipfix_main_t * im = &ipfix_main;
  clib_bihash_kv_48_8_t search, result;
  int status;

  memset(&search, 0, sizeof(clib_bihash_kv_48_8_t));
  memset(&result, 0, sizeof(clib_bihash_kv_48_8_t));

  create_flow_key((ipfix_ip4_flow_key_t*) &search.key, packet);

  status = clib_bihash_search_48_8(&im->flow_hash, &search, &result);

  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);

  if (status < 0) {
    ipfix_ip4_flow_value_t record;

    memcpy(&record.flow_key, &search.key, sizeof(ipfix_ip4_flow_key_t));
    record.flow_start = ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
    record.flow_end = record.flow_start;
    record.packet_delta_count = htonl(1);
    record.octet_delta_count = htonl(ntohs(packet->length));

    vec_add1(im->flow_records, record);
    /* FIXME: this index calculation may not work when we delete
       records later */
    search.value = vec_len(im->flow_records) - 1;

    insert_packet_flow_hash(&search);
  } else {
    // update record
    u32 record_idx = result.value;
    ipfix_ip4_flow_value_t *record = vec_elt_at_index(im->flow_records, record_idx);
    record->flow_end = ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
    record->packet_delta_count = htonl(ntohl(record->packet_delta_count) + 1);
    record->octet_delta_count = htonl(ntohl(record->octet_delta_count) + ntohs(packet->length));
  }
}

static uword
ipfix_node_fn (vlib_main_t * vm,
                  vlib_node_runtime_t * node,
                  vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  ipfix_next_t next_index;
  ipfix_main_t * im = &ipfix_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
                           to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
        {
          u32 next0 = IPFIX_NEXT_INTERFACE_OUTPUT;
          u32 next1 = IPFIX_NEXT_INTERFACE_OUTPUT;
          u32 sw_if_index0, sw_if_index1;
          ip4_header_t *ip0, *ip1;
          u32 bi0, bi1;
          vlib_buffer_t * b0, * b1;

          /* Prefetch next iteration. */
          {
            vlib_buffer_t * p2, * p3;

            p2 = vlib_get_buffer (vm, from[2]);
            p3 = vlib_get_buffer (vm, from[3]);

            vlib_prefetch_buffer_header (p2, LOAD);
            vlib_prefetch_buffer_header (p3, LOAD);

            CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, STORE);
            CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, STORE);
          }

          /* speculatively enqueue b0 and b1 to the current next frame */
          to_next[0] = bi0 = from[0];
          to_next[1] = bi1 = from[1];
          from += 2;
          to_next += 2;
          n_left_from -= 2;
          n_left_to_next -= 2;

          b0 = vlib_get_buffer (vm, bi0);
          b1 = vlib_get_buffer (vm, bi1);

          ip0 = vlib_buffer_get_current (b0);
          ip1 = vlib_buffer_get_current (b1);

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];

          process_packet(ip0);
          process_packet(ip1);

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
            {
              if (b0->flags & VLIB_BUFFER_IS_TRACED)
                {
                    ipfix_trace_t *t =
                      vlib_add_trace (vm, node, b0, sizeof (*t));
                    t->sw_if_index = sw_if_index0;
                    t->next_index = next0;
                    t->flow_hash = im->flow_hash;
                    t->flow_records = vec_dup(im->flow_records);
                  }
                if (b1->flags & VLIB_BUFFER_IS_TRACED)
                  {
                    ipfix_trace_t *t =
                      vlib_add_trace (vm, node, b1, sizeof (*t));
                    t->sw_if_index = sw_if_index1;
                    t->next_index = next1;
                    t->flow_hash = im->flow_hash;
                    t->flow_records = vec_dup(im->flow_records);
                  }
              }

            /* verify speculative enqueues, maybe switch current next frame */
            vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                                             to_next, n_left_to_next,
                                             bi0, bi1, next0, next1);
        }

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 bi0;
          vlib_buffer_t * b0;
          u32 next0 = IPFIX_NEXT_INTERFACE_OUTPUT;
          u32 sw_if_index0;
          ip4_header_t *ip0;

          /* speculatively enqueue b0 to the current next frame */
          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);

          ip0 = vlib_buffer_get_current (b0);

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

          process_packet(ip0);

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                            && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
            ipfix_trace_t *t =
               vlib_add_trace (vm, node, b0, sizeof (*t));
            t->sw_if_index = sw_if_index0;
            t->next_index = next0;
            t->flow_hash = im->flow_hash;
            t->flow_records = vec_dup(im->flow_records);
          }

          /* verify speculative enqueue, maybe switch current next frame */
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

static void ipfix_send_packet(vlib_main_t * vm)
{
  ipfix_main_t * im = &ipfix_main;
  vlib_frame_t * nf;
  vlib_node_t * next_node;
  u32 * to_next;
  vlib_buffer_t * b0;
  ethernet_header_t * en0;
  ip4_header_t * ip0;
  udp_header_t * udp0;
  u32 * buffers = NULL;
  int num_buffers;

  /* FIXME: why would the next node be ip4-lookup? */
  next_node = vlib_get_node_by_name(vm, (u8 *) "ip4-lookup");
  nf = vlib_get_frame_to_node(vm, next_node->index);
  nf->n_vectors = 1;
  to_next = vlib_frame_vector_args(nf);

  /* FIXME: how much buffer does this allocate? */
  /* allocate a buffer, get the index for it into buffers */
  vec_validate(buffers, 0);
  num_buffers = vlib_buffer_alloc(vm, buffers, vec_len(buffers));

  if (num_buffers != 1) {
    clib_warning("Wrong number of buffers allocated %d", num_buffers);
  }

  /* get the actual buffer pointer from our buffer index */
  b0 = vlib_get_buffer(vm, buffers[0]);

  b0->current_data = 0;
  b0->current_length = sizeof(ip4_header_t);
  b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;

  /* VPP generates this buffer so we have to set this flag apparently?
   * https://www.mail-archive.com/vpp-dev@lists.fd.io/msg02656.html */
  b0->flags |= VNET_BUFFER_LOCALLY_ORIGINATED;

  ip0 = b0->data;
  ip0->ip_version_and_header_length = 0x45;
  ip0->tos = 0;
  ip0->length = clib_byte_swap_u16(20);
  ip0->fragment_id = 0;
  ip0->flags_and_fragment_offset = 0;
  ip0->ttl = 64;
  ip0->protocol = 17;
  ip0->checksum = 0;

  clib_memcpy(&ip0->src_address.data, &im->exporter_ip.data, sizeof(ip4_address_t));
  clib_memcpy(&ip0->dst_address.data, &im->collector_ip.data, sizeof(ip4_address_t));

  /* set to_next index to the buffer index we allocated */
  *to_next = buffers[0];
  to_next++;

  vlib_put_frame_to_node(vm, next_node->index, nf);
}

static uword ipfix_process_records_fn(vlib_main_t * vm,
                                   vlib_node_runtime_t * node,
                                   vlib_frame_t * frame)
{
  f64 poll_time_remaining = PROCESS_POLL_PERIOD;
  ipfix_main_t * im = &ipfix_main;
  ipfix_ip4_flow_value_t *record;
  u64 idle_flow_timeout = 10 * 1e3;
  u64 active_flow_timeout = 30 * 1e3;

  while (1) {
    poll_time_remaining = vlib_process_wait_for_event_or_clock(vm, poll_time_remaining);
    struct timespec current_time_clock;
    clock_gettime(CLOCK_REALTIME, &current_time_clock);
    u64 current_time = current_time_clock.tv_sec * 1e3 + current_time_clock.tv_nsec / 1e6;
    u64 record_idx = 0;

    vec_foreach_index(record_idx, im->flow_records) {
      clib_warning("Vector length: %d", vec_len(im->flow_records));

      record = vec_elt_at_index(im->flow_records, record_idx);

      if ((record->flow_end + idle_flow_timeout) < current_time) {
        clib_warning("IPFix has expired a idle flow %U", format_ipfix_ip4_flow, record);
        vec_add1(im->expired_records, *record);
        vec_del1(im->flow_records, record_idx);

        clib_bihash_kv_48_8_t keyvalue;
        memset(&keyvalue, 0, sizeof(clib_bihash_kv_48_8_t));
        memcpy(&keyvalue.key, &record->flow_key, sizeof(ipfix_ip4_flow_key_t));
        if (clib_bihash_add_del_48_8(&im->flow_hash, &keyvalue, 0) != 0) {
          clib_warning("Warning: Could not remove flow form hash.");
        };

        ipfix_send_packet(im->vlib_main);
      } else if ((record->flow_start + active_flow_timeout) < current_time) {
        clib_warning("IPFIX has expired an active flow. %U\n", format_ipfix_ip4_flow, record);
        vec_add1(im->expired_records, *record);

        record->flow_start = current_time;
        record->flow_end = current_time;
        record->packet_delta_count = 0;
        record->octet_delta_count = 0;
      }
    };

    if (vlib_process_suspend_time_is_zero(poll_time_remaining)) {
      poll_time_remaining = PROCESS_POLL_PERIOD;
    }
  }
  return 0;
}


VLIB_REGISTER_NODE (ipfix_process_records) = {
  .function = ipfix_process_records_fn,
  .name = "ipfix-record-processing",
  .type = VLIB_NODE_TYPE_PROCESS,
};


VLIB_REGISTER_NODE (ipfix_node) = {
  .function = ipfix_node_fn,
  .name = "ipfix",
  .vector_size = sizeof (u32),
  .format_trace = format_ipfix_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(ipfix_error_strings),
  .error_strings = ipfix_error_strings,

  .n_next_nodes = IPFIX_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [IPFIX_NEXT_INTERFACE_OUTPUT] = "ip4-lookup",
  },
};
