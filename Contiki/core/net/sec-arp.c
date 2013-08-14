/*
 * sec-arp.c
 *
 *  Created on: Aug 5, 2013
 *      Author: crea
 */
#include "net/sec-arp.h"
#include "dev/xmem.h"

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...) do {} while (0)
#endif

/*-----------------------------------------------------------------------------------*/
/**
 * Create Hello packet CODE
 */
/*-----------------------------------------------------------------------------------*/
void
create_hello(uint8_t *buf)
{
	hello_packet_t packet;

	/* Construct packet */
	packet.type = HELLO_PACKET;
	packet.operation = SEC_ARP_REQUEST;

	buf[0] = packet.type;
	buf[1] = packet.operation;

	PRINTF("sec-arp: create\n");
}
//void
//create_hello(uint8_t *buf)
//{
//	hello_packet_t packet;
//	uint8_t i;
//
//	/* Construct packet */
//	packet.type = HELLO_PACKET;
//	packet.operation = SEC_ARP_REPLY;
//
//	buf[0] = packet.type;
//	buf[1] = packet.operation;
//
//	for(i=0; i<16; i++)
//	{
//		buf[2+i] = i;
//	}
//	buf[18]= 0;
//
//	for(i=0; i<16; i++)
//	{
//		buf[19+i]= 2;
//	}
//
//	PRINTF("sec-arp: create\n");
//}
/*-----------------------------------------------------------------------------------*/
/**
 * Parse hello reply packet
 *
 * fromat: | network key(16) | link_nonce_cntr(1) | sensor key(16) |
 */
/*-----------------------------------------------------------------------------------*/
short
parse_hello_reply(uint8_t *buf)
{
	PRINTF("sec-arp: parse\n");

	if(buf[0] != HELLO_PACKET) {
		return 0;
	}

	if(buf[1] != SEC_ARP_REPLY) {
		return 0;
	}

	xmem_erase(XMEM_ERASE_UNIT_SIZE, MAC_SECURITY_DATA);
	xmem_pwrite(&buf[2], 33, MAC_SECURITY_DATA);

	PRINTF("sec-arp: parse OK\n");

	return 1;
}
