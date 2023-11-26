#ifndef SHOCKBURST_PACKET_H
#define SHOCKBURST_PACKET_H

#include <stdint.h>


class shockburst_packet
{
public:

  // Constructor
  shockburst_packet(uint8_t address_length,
                             uint8_t big_packet,
                             uint8_t payload_length,
                             uint8_t sequence_number,
                             uint8_t no_ack,
                             uint8_t crc_length,
                             uint8_t * address,
                             uint8_t * payload
                             );

  // Destructur
  ~shockburst_packet();

  // Attempt to parse a packet from some incoming bytes
  static bool try_parse(const uint8_t * bytes,
                        const uint8_t ** addresses,
                        const uint8_t * address_match_len,
                        uint8_t address_length,
                        uint8_t payload_length,
                        uint8_t crc_length,
                        shockburst_packet *& packet);

  static bool _try_parse(const uint8_t* bytes,
                        const uint8_t** addresses,
                        const uint8_t* address_match_len,
                        uint8_t address_length,
                        uint8_t payload_length,
                        uint8_t crc_length,
                        shockburst_packet*& packet,
                        bool big_packet);

  // Process a crc byte (or partial byte)
  static uint16_t crc_update (uint16_t crc, uint8_t data, uint8_t bits=8);

  // Print the packet details to standard out
  void print();

  // Getters
  const uint8_t payload_length() { return m_payload_length; }
  //const uint8_t address_length() { return m_address_length; }
  const uint8_t bytes_length() { return m_packet_length_bytes; }
  const uint8_t sequence_number() { return m_sequence_number; }
  const uint8_t no_ack() { return m_no_ack; }
  const uint8_t * address() { return m_address; }
  const uint8_t * payload() { return m_payload; }
  const uint8_t * crc() { return m_crc; }
  const uint8_t * bytes() { return m_packet_bytes; }
  const uint8_t big_packet() { return m_big_packet; }

private:

  // Address length
  uint8_t m_address_length;

  // Big packet protocol
  bool m_big_packet;

  // Payload length
  uint8_t m_payload_length;

  // Packet length
  uint8_t m_packet_length_bytes;
  uint16_t m_packet_length_bits;

  // Sequence number (ESB)
  uint8_t m_sequence_number;

  // No ACK bit (ESB)
  bool m_no_ack;

  // CRC length
  uint8_t m_crc_length;

  // Address
  uint8_t * m_address;

  // Payload
  uint8_t * m_payload;

  // CRC
  uint8_t * m_crc;

  // Assembled packet bytes
  uint8_t * m_packet_bytes;

} __attribute__((packed));

#endif // SHOCKBURST_PACKET_H
