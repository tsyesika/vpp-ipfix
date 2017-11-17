#include <vnet/vnet.h>

// IPFIX fields. TODO: Parse from CSV file.
#define protocolIdentifier 4
#define sourceTransportPort 7
#define sourceIPv4Address 8
#define destinationTransportPort 11
#define destinationIPv4Address 12
#define flowStartMilliseconds 152
#define flowEndMilliseconds 153

typedef struct {
  u16 version;
  u16 byte_length;
  u32 timestamp;
  u32 sequence_number;
  u32 observation_domain;
} netflow_v10_header_t;

/* Structures for templates */
typedef struct {
  u16 identifier;
  u16 size; // In octets.
  u32 enterprise_number;
} netflow_v10_field_specifier_t;

typedef struct {
  u16 id;

  /* Vector of fields */
  netflow_v10_field_specifier_t *fields;
} netflow_v10_template_set_t;

typedef struct {
  /* Vector of sets. */
  netflow_v10_template_set_t *sets;
} netflow_v10_template_t;
/* Structures for data packets */

typedef struct {
  u8 *data; // Pointer to some data with the packet data.
} netflow_v10_data_record_t;

typedef struct {
  u16 id;
  netflow_v10_data_record_t *fields;
} netflow_v10_data_record_set_t;

typedef struct {
  netflow_v10_header_t header;
  netflow_v10_data_record_set_t *sets;
} netflow_v10_data_packet_t;
