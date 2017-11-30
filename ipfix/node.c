
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

/* TODO: Replace with the user configurable template.
 * Parsed from the CSV file describing the fields
 */
static void ipfix_make_v10_template(netflow_v10_template_t *template)
{
  /* Initialize an empty flow key to calculate the offsets against. */
  ipfix_ip4_flow_value_t record;

  /* Initialize the set vector. */
  template->sets = 0;

  /* Create a single set for these */
  netflow_v10_template_set_t set;
  /* Data record sets start from #256 */
  set.id = 256;
  set.fields = 0; // Initialize the fields vector.

  netflow_v10_field_specifier_t src_address;
  src_address.identifier = sourceIPv4Address;
  src_address.size = sizeof(u8) * 4;
  src_address.record_offset = (size_t)&record.flow_key.src - (size_t)&record;
  vec_add1(set.fields, src_address);

  netflow_v10_field_specifier_t dst_address;
  dst_address.identifier = destinationIPv4Address;
  dst_address.size = sizeof(u8) * 4;
  dst_address.record_offset = (size_t)&record.flow_key.dst - (size_t)&record;
  vec_add1(set.fields, dst_address);

  netflow_v10_field_specifier_t protocol;
  protocol.identifier = protocolIdentifier;
  protocol.size = sizeof(u8);
  protocol.record_offset = (size_t)&record.flow_key.protocol - (size_t)&record;
  vec_add1(set.fields, protocol);

  netflow_v10_field_specifier_t src_port;
  src_port.identifier = sourceTransportPort;
  src_port.size = sizeof(u16);
  src_port.record_offset = (size_t)&record.flow_key.src_port - (size_t)&record;
  vec_add1(set.fields, src_port);

  netflow_v10_field_specifier_t dst_port;
  dst_port.identifier = destinationTransportPort;
  dst_port.size = sizeof(u16);
  dst_port.record_offset = (size_t)&record.flow_key.dst_port - (size_t)&record;
  vec_add1(set.fields, dst_port);

  netflow_v10_field_specifier_t flow_start;
  flow_start.identifier = flowStartMilliseconds;
  flow_start.size = sizeof(u64);
  flow_start.record_offset = (size_t)&record.flow_start - (size_t)&record;
  vec_add1(set.fields, flow_start);

  netflow_v10_field_specifier_t flow_end;
  flow_end.identifier = flowEndMilliseconds;
  flow_end.size = sizeof(u64);
  flow_end.record_offset = (size_t)&record.flow_end - (size_t)&record;
  vec_add1(set.fields, flow_end);

  netflow_v10_field_specifier_t octet_count;
  octet_count.identifier = octetDeltaCount;
  octet_count.size = sizeof(u64);
  octet_count.record_offset = (size_t)&record.octet_delta_count - (size_t)&record;
  vec_add1(set.fields, octet_count);

  netflow_v10_field_specifier_t packet_count;
  packet_count.identifier = packetDeltaCount;
  packet_count.size = sizeof(u64);
  packet_count.record_offset = (size_t)&record.packet_delta_count - (size_t)&record;
  vec_add1(set.fields, packet_count);

  vec_add1(template->sets, set);
}

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

  s = format(s, "\n[Flow key] src: %U, dst: %U, protocol: %u, src port: %U, dst port: %U\n",
             format_ip4_address, &flow_key.src,
             format_ip4_address, &flow_key.dst,
             flow_key.protocol,
             format_tcp_udp_port, flow_key.src_port,
             format_tcp_udp_port, flow_key.dst_port);
  s = format(s, "[Flow record] start: %U, end: %U, count: %u, octets: %u\n",
             format_timestamp, flow_record->flow_start,
             format_timestamp, flow_record->flow_end,
             ntohl(flow_record->packet_delta_count),
             ntohl(flow_record->octet_delta_count));

  return s;
}

static u8* format_netflow_v10_template(u8 *s, va_list *args) {
  netflow_v10_template_t *template = va_arg (*args, netflow_v10_template_t*);
  netflow_v10_template_set_t *set;
  s = format(s, "Netflow V10 Template:\n");
  vec_foreach(set, template->sets) {
    netflow_v10_field_specifier_t *field;
    s = format(s, "\tSet %u:\n", set->id);
    vec_foreach(field, set->fields) {
      s = format(s, "\t\t");

      switch (field->identifier) {
      case protocolIdentifier:
        s = format(s, "protocolIdentifier (%d)\t\t", field->identifier);
        break;
      case sourceTransportPort:
        s = format(s, "sourceTransportPort (%u)\t\t", field->identifier);
        break;
      case sourceIPv4Address:
        s = format(s, "sourceIPv4Address (%u)\t\t", field->identifier);
        break;
      case destinationTransportPort:
        s = format(s, "destinationTransportPort (%u)\t", field->identifier);
        break;
      case destinationIPv4Address:
        s = format(s, "destinationIPv4Address (%u)\t", field->identifier);
        break;
      case flowStartMilliseconds:
        s = format(s, "flowStartMilliseconds (%u)\t", field->identifier);
        break;
      case flowEndMilliseconds:
        s = format(s, "flowEndMilliseconds (%u)\t", field->identifier);
        break;
      case octetDeltaCount:
        s = format(s, "octetDeltaCount (%u)\t\t", field->identifier);
        break;
      case packetDeltaCount:
        s = format(s, "packetDeltaCount (%u)\t\t", field->identifier);
        break;
      default:
        s = format(s, "-- unsupported -- (%u)\t\t", field->identifier);
      };

      s = format(s, "octets: %u\t\tenterprise number: %u\n",
                 field->size, field->enterprise_number);
    };
  };
  s = format(s, "End of V10 Template\n");
  return s;
}

static u8* format_netflow_v10_data_packet(u8 *s, va_list *args) {
  netflow_v10_data_packet_t *packet = va_arg (*args, netflow_v10_data_packet_t*);
  netflow_v10_template_set_t *template_set;
  netflow_v10_data_set_t *data_set;
  netflow_v10_field_specifier_t *field_spec;
  netflow_v10_template_t template;
  ipfix_make_v10_template(&template);

  s = format(s, "Netflow V10 Data Packet:\n");

  // The data packet is build to mirror the template with data, It _should_ be
  // safe to use the same indices.
  u64 set_idx;
  void *data;
  vec_foreach_index(set_idx, template.sets) {
      template_set = vec_elt_at_index(template.sets, set_idx);
      data_set = vec_elt_at_index(packet->sets, set_idx);
      format(s, "\tSet %u:\n", template_set->id);

      data = data_set->data;
      u64 field_idx;
      vec_foreach_index(field_idx, template_set->fields) {
        field_spec = vec_elt_at_index(template_set->fields, field_idx);

        switch (field_spec->identifier) {
        case sourceIPv4Address:
          s = format(s, "\t\t%U", format_ip4_address, (ip4_address_t *)data_set->data);
          break;
        case destinationIPv4Address:
          s = format(s, "\t\t%U", format_ip4_address, data);
          break;
        case protocolIdentifier:
          s = format(s, "\t\t%u", ntohl(*(u16 *)data));
          break;
        case sourceTransportPort:
          s = format(s, "\t\t%U", format_tcp_udp_port, *(u16 *)data);
          break;
        case destinationTransportPort:
          s = format(s, "\t\t%U", format_tcp_udp_port, *(u16 *)data);
          break;
        case flowStartMilliseconds:
          s = format(s, "\t\t%U", format_timestamp, *(u64 *)data);
          break;
        case flowEndMilliseconds:
          s = format(s, "\t\t%U", format_timestamp, *(u64 *)data);
          break;
        case octetDeltaCount:
          s = format(s, "\t\t%u", ntohl(*(u64 *)data));
          break;
        case packetDeltaCount:
          s = format(s, "\t\t%u", ntohl(*(u64 *)data));
          break;
        default:
          ASSERT(0); // This shouldn't happen - makes the packet unreadable.
        }
        data = (void *)((size_t)data + field_spec->size);
        s = format(s, "\n");
      };
  };

  s = format(s, "End of packet\n");

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

static void ipfix_free_v10_packet(netflow_v10_data_packet_t *packet)
{
  netflow_v10_data_set_t *set;
  vec_foreach(set, packet->sets) {
    free(set->data);
  };
  vec_free(packet->sets);
}

static void ipfix_build_v10_packet(ipfix_ip4_flow_value_t *record,
                                   netflow_v10_data_packet_t *packet)
{
  u64 byte_length = sizeof(netflow_v10_header_t);
  ipfix_main_t * im = &ipfix_main;
  netflow_v10_template_t template;
  ipfix_make_v10_template(&template);

  clib_warning("%U", format_netflow_v10_template, &template);

  struct timespec current_time_clock;
  clock_gettime(CLOCK_REALTIME, &current_time_clock);


  packet->sets = 0;
  packet->header.version = ntohs(10);
  packet->header.timestamp = ntohs(current_time_clock.tv_sec);
  /* FIXME: the sequence number is incremented by 1 each time because
   * for now each packet only has a single record, but in general we
   * will have multiple records
   */
  im->sequence_number += 1;
  packet->header.sequence_number = clib_byte_swap_u32(im->sequence_number);
  /* set length field in header at end */

  netflow_v10_template_set_t *set;
  netflow_v10_field_specifier_t *field;
  vec_foreach(set, template.sets) {
    u64 data_size = 0;
    vec_foreach(field, set->fields) {
      data_size = data_size + field->size;
    }
    byte_length += data_size + sizeof(netflow_v10_set_header_t);

    netflow_v10_data_set_t active_set;
    active_set.data = malloc(data_size);
    void *ptr = (size_t)active_set.data;
    vec_foreach(field, set->fields) {
      memcpy(ptr, (void *)((size_t)record + field->record_offset), field->size);

      // Advance the pointer to the next field.
      ptr = (void *)((size_t)ptr + field->size);
    };

    vec_add1(packet->sets, active_set);
  };

  packet->header.byte_length = ntohs(byte_length);
}

/* Write a template set to the given buffer (which must have enough
 * space allocated) for an IPFIX packet
 *
 * Returns the number of bytes written to buffer
 */
static u64 ipfix_write_template_set(void *buffer) {
  u16* ptr = (u16*) buffer;
  u64 octets;
  u64 set_idx;
  netflow_v10_header_t *ipfix_header;
  u16* template_header;
  netflow_v10_template_set_t *template_set;
  netflow_v10_template_t template;
  netflow_v10_field_specifier_t *field_spec;
  struct timespec current_time_clock;
  ipfix_main_t * im = &ipfix_main;

  ipfix_make_v10_template(&template);
  clock_gettime(CLOCK_REALTIME, &current_time_clock);

  /* advance pointer past header, write header at end */
  ipfix_header = (netflow_v10_header_t*) ptr;
  template_header = ptr + sizeof(netflow_v10_header_t) / 2;
  ptr = template_header + 2;
  octets = sizeof(netflow_v10_header_t) + 4;

  vec_foreach_index(set_idx, template.sets) {
    template_set = vec_elt_at_index(template.sets, set_idx);

    *ptr = clib_byte_swap_u16(template_set->id);
    *(ptr + 1) = clib_byte_swap_u16(vec_len(template_set->fields));
    ptr += 2;
    octets += 4;

    vec_foreach(field_spec, template_set->fields) {
      *ptr = clib_byte_swap_u16(field_spec->identifier);
      *(ptr + 1) = clib_byte_swap_u16(field_spec->size);
      ptr += 2;
      octets += 4;
    };
  }

  /* write IPFIX header */
  ipfix_header->version = clib_byte_swap_u16(10);
  ipfix_header->byte_length = clib_byte_swap_u16(octets);
  ipfix_header->timestamp = clib_byte_swap_u32(current_time_clock.tv_sec);
  ipfix_header->sequence_number = clib_byte_swap_u32(im->sequence_number);
  ipfix_header->observation_domain = clib_byte_swap_u32(1);

  /* write set header */
  *template_header = clib_byte_swap_u16(2);
  *(template_header + 1) = clib_byte_swap_u16(octets - sizeof(netflow_v10_header_t));

  return octets;
}

/* Writes `packet` to `buffer`. The buffer MUST have enough space allocated to fit the entire
 * packet.
 *
 * Returns number of bytes written to buffer.
 */
static u64 ipfix_write_v10_data_packet(void *buffer, netflow_v10_data_packet_t *packet)
{
  netflow_v10_data_set_t *data_set;
  netflow_v10_template_set_t *template_set;
  netflow_v10_field_specifier_t *field_spec;
  netflow_v10_template_t template;
  ipfix_make_v10_template(&template);

  u64 written = 0;
  u64 set_idx;
  void *ptr = buffer;

  memcpy(ptr, &packet->header, sizeof(netflow_v10_header_t));
  ptr = (void*)((size_t)ptr + sizeof(netflow_v10_header_t));
  written += (u64)sizeof(netflow_v10_header_t);

  vec_foreach_index(set_idx, template.sets) {
    template_set = vec_elt_at_index(template.sets, set_idx);
    data_set = vec_elt_at_index(packet->sets, set_idx);

    // Calculate the length of the set.
    size_t header_length = sizeof(netflow_v10_set_header_t);
    size_t data_length = 0;
    vec_foreach(field_spec, template_set->fields) {
      data_length = data_length + field_spec->size;
    };

    // Should be able to just memcopy the entire set, data 'n all.
    data_set->header.id = htons(template_set->id);
    data_set->header.length = htons(header_length + data_length);
    memcpy(ptr, &data_set->header, header_length);
    ptr = (void*)((size_t)ptr + header_length);
    memcpy(ptr, data_set->data, data_length);
    written = written + (u64)header_length + (u64)data_length;

    // Advence the pointer past the set.
    ptr = (void *)((size_t)ptr + header_length + data_length);
  };

  return written;
}

/* Send an IPFIX packet based on the given data records or send a template packet
 * if is_template is 1
 * FIXME: this interface is kind of awkward
 */
static void ipfix_send_packet(vlib_main_t * vm, u8 is_template, netflow_v10_data_packet_t *packet)
{
  ipfix_main_t * im = &ipfix_main;
  vlib_frame_t * nf;
  vlib_node_t * next_node;
  u32 * to_next;
  vlib_buffer_t * b0;
  ip4_header_t * ip0;
  udp_header_t * udp0;
  u32 * buffers = NULL;
  int num_buffers;
  void * payload;
  int payload_length;

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
  b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;

  /* VPP generates this buffer so we have to set this flag apparently?
   * https://www.mail-archive.com/vpp-dev@lists.fd.io/msg02656.html */
  b0->flags |= VNET_BUFFER_LOCALLY_ORIGINATED;

  ip0 = (ip4_header_t*) b0->data;
  ip0->ip_version_and_header_length = 0x45;
  ip0->tos = 0;
  ip0->fragment_id = 0;
  ip0->flags_and_fragment_offset = 0;
  ip0->ttl = 64;
  ip0->protocol = 17;
  ip0->checksum = 0;

  clib_memcpy(&ip0->src_address.data, &im->exporter_ip.data, sizeof(ip4_address_t));
  clib_memcpy(&ip0->dst_address.data, &im->collector_ip.data, sizeof(ip4_address_t));

  udp0 = (udp_header_t*) (ip0 + 1);
  udp0->src_port = clib_byte_swap_u16(im->exporter_port);
  udp0->dst_port = clib_byte_swap_u16(im->collector_port);

  payload = (void*) (udp0 + 1);
  if (is_template) {
    payload_length = ipfix_write_template_set(payload);
  } else {
    payload_length = ipfix_write_v10_data_packet(payload, packet);
  }

  /* set all lengths at once */
  b0->current_length = sizeof(ip4_header_t) + sizeof(udp_header_t) + payload_length;
  ip0->length = clib_byte_swap_u16(20 + 8 + payload_length);
  udp0->length = clib_byte_swap_u16(8 + payload_length);

  /* set to_next index to the buffer index we allocated */
  *to_next = buffers[0];
  to_next++;

  vlib_put_frame_to_node(vm, next_node->index, nf);
}

static uword ipfix_process_records_fn(vlib_main_t * vm,
                                   vlib_node_runtime_t * node,
                                   vlib_frame_t * frame)
{
  static u64 last_template = 0;
  f64 poll_time_remaining = PROCESS_POLL_PERIOD;
  ipfix_main_t * im = &ipfix_main;
  ipfix_ip4_flow_value_t *record;
  u64 idle_flow_timeout = 10 * 1e3;
  u64 active_flow_timeout = 30 * 1e3;
  u64 template_timeout = 10 * 1e3;

  while (1) {
    poll_time_remaining = vlib_process_wait_for_event_or_clock(vm, poll_time_remaining);
    struct timespec current_time_clock;
    clock_gettime(CLOCK_REALTIME, &current_time_clock);
    u64 current_time = current_time_clock.tv_sec * 1e3 + current_time_clock.tv_nsec / 1e6;
    u64 record_idx = 0;

    if (last_template + template_timeout < current_time) {
      ipfix_send_packet(im->vlib_main, 1, NULL);
      last_template = current_time;
    }

    vec_foreach_index(record_idx, im->flow_records) {
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
      } else if ((record->flow_start + active_flow_timeout) < current_time) {
        clib_warning("IPFIX has expired an active flow. %U\n", format_ipfix_ip4_flow, record);
        vec_add1(im->expired_records, *record);

        record->flow_start = current_time;
        record->flow_end = current_time;
        record->packet_delta_count = 0;
        record->octet_delta_count = 0;
      }
    };

    vec_foreach_index(record_idx, im->expired_records) {
      netflow_v10_data_packet_t packet;
      record = vec_elt_at_index(im->expired_records, record_idx);
      ipfix_build_v10_packet(record, &packet);
      vec_add1(im->data_packets, packet);
      vec_del1(im->expired_records, record_idx);
    };

    netflow_v10_data_packet_t *packet;
    u64 packet_idx;
    vec_foreach_index(packet_idx, im->data_packets) {
      packet = vec_elt_at_index(im->data_packets, packet_idx);
      clib_warning("%U", format_netflow_v10_data_packet, packet);

      /* FIXME: Instead of looping over packets and sending each one, the
                loop should be in the function to fill up a frame with
                multiple packets at a time */
      ipfix_send_packet(im->vlib_main, 0, packet);

      ipfix_free_v10_packet(packet);
      vec_del1(im->data_packets, packet_idx);
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
