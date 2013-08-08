/*
 * sec-arp.h
 *
 *  Created on: Aug 5, 2013
 *      Author: crea
 */

#ifndef SEC_ARP_H_
#define SEC_ARP_H_

#include "platform-conf.h"

typedef struct {
  uint8_t type;
  uint8_t operation;
} hello_packet_t;

/* Defines the reply packet length */
#define HELLO_REPLY_PACKETSIZE 35

#define HELLO_PACKET 	1
#define HELLO_ACK	 	2
#define SEC_ARP_REQUEST	1
#define SEC_ARP_REPLY	2

void create_hello(uint8_t *buf);
short parse_hello_reply(uint8_t *buf);

#endif /* SEC_ARP_H_ */
