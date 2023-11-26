#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "shockburst_packet.h"

shockburst_packet::shockburst_packet(uint8_t address_length,
                                                       uint8_t big_packet,
                                                       uint8_t payload_length,
                                                       uint8_t sequence_number,
                                                       uint8_t no_ack,
                                                       uint8_t crc_length,
                                                       uint8_t * address,
                                                       uint8_t * payload
                                                       ) :
  m_address_length(address_length),
  m_big_packet(big_packet),
  m_payload_length(payload_length),
  m_sequence_number(sequence_number),
  m_no_ack(no_ack),
  m_crc_length(crc_length)
{
  // Allocate buffers
  m_address = new uint8_t[m_address_length];
  m_payload = new uint8_t[m_payload_length];
  m_crc = new uint8_t[m_crc_length];

  // Copy over address and payload
  memcpy(m_address, address, m_address_length);
  memcpy(m_payload, payload, m_payload_length);

  // Build the packet bytes
  const int blen = 1 /* preamble */ +
                   m_crc_length +
                   m_address_length +
                   m_payload_length;
  m_packet_length_bytes = blen;
  m_packet_length_bits = blen*8;
  m_packet_bytes = new uint8_t[blen];

  memset(m_packet_bytes, 0, blen);

  // Preamble
  if((address[0] & 0x80) == 0x80) m_packet_bytes[0] = 0xAA;
  else m_packet_bytes[0] = 0x55;

  // Address
  memcpy(&m_packet_bytes[1], address, m_address_length);


  uint8_t alignment_offset = 0;

  // Payload
  for(int b = 0; b < m_payload_length; b++)
  {
    m_packet_bytes[1 + m_address_length + b] |= (payload[b] >> alignment_offset);
    m_packet_bytes[2 + m_address_length + b] |= (payload[b] << (8 - alignment_offset));
  } 
	//memcpy(&m_packet_bytes[1+m_address_length], payload, m_payload_length);

  // Calculate the CRC 
  uint16_t crc = 0xFFFF;
  for(int b = 1; b < 7 + m_payload_length-1; b++) //// include address_length in 7?
      crc = crc_update(crc, m_packet_bytes[b]);
  //!!Subtracted 1
  crc = crc_update(crc, m_packet_bytes[7 + m_payload_length-1] & (0xFF << (8 - alignment_offset)), alignment_offset); // include address_length in 7?

  memcpy(m_crc, &crc, m_crc_length);

  // SUBTRActed 1
  m_packet_bytes[1 + m_address_length + m_payload_length] |= ((crc >> (8 + alignment_offset)) & 0xFF);
  m_packet_bytes[2 + m_address_length + m_payload_length] |= ((crc >> alignment_offset) & 0xFF);
  m_packet_bytes[3 + m_address_length + m_payload_length] |= ((crc << (8 - alignment_offset)) & (0xFF << (8 - alignment_offset)));
 
  	//memcpy(&m_packet_bytes[1+ m_address_length+m_payload_length], m_crc, m_crc_length);
}

// Destructur
shockburst_packet::~shockburst_packet()
{
  delete[] m_address;
  delete[] m_payload;
  delete[] m_crc;
}

// Attempt to parse a packet from some incoming bytes using small packet protocol first, then large packet protocol
bool shockburst_packet::try_parse(const uint8_t * bytes,
                                           const uint8_t ** addresses,
                                           const uint8_t *address_match_len,
                                           uint8_t address_length,
                                           uint8_t payload_length,
                                           uint8_t crc_length,
                                           shockburst_packet *& packet)
{
    if (!shockburst_packet::_try_parse(bytes,
                                                     addresses,
                                                     address_match_len,
                                                     address_length,
                                                     payload_length,
                                                     crc_length,
                                                     packet,
                                                     false))
    {
        return false;
    }

    return true;
}

bool shockburst_packet::_try_parse(const uint8_t * bytes,
    const uint8_t ** addresses,
    const uint8_t * address_match_len,
    uint8_t address_length,
    uint8_t payload_length,
    uint8_t crc_length,
    shockburst_packet * &packet,
    bool big_packet)
{

  uint8_t alignment_offset = 0;	// Renove when removed from below
  
  // Read the address
  uint8_t * address = new uint8_t[address_length];
  memcpy(address, &bytes[1], address_length);
  		
  //printf("Address:\n");
  //for(int x = 0; x < address_length; x++) printf("%02X ", address[x]);
  //printf("\n");
		
  // Read the payload
  uint8_t payload[32];
  //printf("Payload:\n");
  for (int b = 0; b < payload_length; b++)
  {
    payload[b] = bytes[6 + b];
      //payload[b] |= bytes[8 + b] >> (8 - alignment_offset);
      //printf("%02X\n", payload[b]);
  }
  	
  // Read the given CRC
  	//printf(" CRC bytes %02X ",bytes[1 + address_length + payload_length]);
  	//printf("%02X\n",bytes[2 + address_length + payload_length]);
  uint16_t crc_given;
  //subtracted 1
  crc_given = bytes[1 + address_length + payload_length] & (0xFF >> alignment_offset);
  crc_given <<= 8;
  crc_given |= bytes[2 + address_length + payload_length];
  //crc_given <<= alignment_offset;
  crc_given |= bytes[3 + address_length + payload_length] >> (8 - alignment_offset) ;
  crc_given = htons(crc_given);
	//printf("given CRC: %d\n", crc_given);

  // Calculate the CRC
  uint16_t crc = 0xFFFF;
  for(int b = 1; b < 7 + payload_length-1; b++) crc = crc_update(crc, bytes[b]); // include address_length in 7?
  crc = crc_update(crc, bytes[7 + payload_length-1] & (0xFF << (8 - alignment_offset)),  alignment_offset); // include address_length in 7?
  crc = htons(crc);
	//printf("calculated CRC: %d\n", crc);
	
  // Validate the CRC
  if(memcmp(&crc, &crc_given, 2) != 0)
  {
      // If we've been provided a list of possible addresses, look for those so we can report CRC errors
      // Only check this if we're in the big_packet round of parsing, otherwise will report valid BP		
      // packets during the non-BP parsing round.
      		/*
      if (address_match_len && big_packet)
      {
          const uint8_t* cur_match_len = address_match_len;
          const uint8_t** cur_addr_match = addresses;
	  
          while (*cur_match_len)
          {
              if (memcmp(address, *cur_addr_match, *cur_match_len) == 0)
              {
                  printf("Possible NRF packet with CRC error (given: %04X, calculated: %04X, length: %d, address: ",
                        crc_given, crc, payload_length);
                  for (int i = 0; i < address_length; i++) printf("%02X",address[i]);
                  printf(")\n");
                  break;
              }
              cur_match_len++;
              cur_addr_match++;
          }
      }
      		*/
      delete[] address;
      		//printf("CRC_missmatch\n");	//!!!!!!!!!!!!!!!!
      return false;
  }

  // Read the sequence number and no-ACK bit
  // Set to zero, the SB protocol does not contain seq or ack
  uint8_t seq = 0;//bytes[6] & 0x3;
  uint8_t no_ack = 0;//bytes[7] >> 7;
	
  // Update the fields
  packet = new shockburst_packet(address_length, 
                                          big_packet,
                                          payload_length, 
                                          seq,
                                          no_ack,
                                          crc_length,
                                          address,
                                          payload);
  
  // Cleanup
  delete[] address;

  return true;
}

// Print the packet details to standard out
void shockburst_packet::print()
{
  printf("Address: ");
  for(int x = 0; x < m_address_length; x++) printf("%02X ", m_address[x]);
  printf("\n");

  printf("Payload: ");
  for(int x = 0; x < m_payload_length; x++) printf("%02X ", m_payload[x]);
  printf("\n");

  printf("CRC:     ");
  for(int x = 0; x < m_crc_length; x++) printf("%02X ", m_crc[x]);
  printf("\n");

  printf("Bytes:   ");
  for(int x = 0; x < m_packet_length_bytes; x++) printf("%02X ", m_packet_bytes[x]);
  printf("BP:      %d\n", m_big_packet);
  printf("ACK:     %d\n", m_no_ack);
  
  printf("\n"); 

  printf("\n");
}

// Process a crc byte (or partial byte)
uint16_t shockburst_packet::crc_update (uint16_t crc, uint8_t data, uint8_t bits)
{
  crc = crc ^ ((uint16_t)data << 8);
  for (int x = 0; x < bits; x++)
  {
    if(crc & 0x8000) crc = (crc << 1) ^ 0x1021;
    else crc <<= 1;
  }
  return crc;
}
