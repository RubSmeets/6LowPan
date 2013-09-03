/*
 * sec-arp.c
 *
 *  Created on: Aug 5, 2013
 *      Author: crea
 */
#include "net/sec-arp.h"
#include "dev/xmem.h"

#include <string.h>

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...) do {} while (0)
#endif

#define LINKLAYER_OFFSET	2
#define APPLAYER_OFFSET		19
#define SEC_DATA_SIZE 		33

/*-----------------------------------------------------------------------------------*/
/**
 * Create Hello packet CODE
 *
 * format: | message_type(1) | operation(1) | device id(16)
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
 * format: | message_type(1) | operation(1) | network key(16) | link_nonce_cntr(1) | edge-router id(16) | sensor key(16) |
 */
/*-----------------------------------------------------------------------------------*/
short
parse_hello_reply(uint8_t *buf)
{
	uint8_t temp_buf[SEC_DATA_SIZE];

	PRINTF("sec-arp: parse\n");

	if(buf[0] != HELLO_PACKET) {
		return 0;
	}

	if(buf[1] != SEC_ARP_REPLY) {
		return 0;
	}

	memcpy(&temp_buf[0], &buf[APPLAYER_OFFSET], SEC_DATA_SIZE-1);
	temp_buf[SEC_DATA_SIZE-1] = 0x01;


	/* Write link-layer security data to flash */
	xmem_erase(XMEM_ERASE_UNIT_SIZE, MAC_SECURITY_DATA);
	xmem_pwrite(&buf[LINKLAYER_OFFSET], 17, MAC_SECURITY_DATA);

	/* Write application-layer security data to flash */
	xmem_erase(XMEM_ERASE_UNIT_SIZE, APP_SECURITY_DATA);
	xmem_pwrite(&temp_buf[0], SEC_DATA_SIZE, APP_SECURITY_DATA);

	/* Write nonce to flash  (clear key-exchange nonces) */
	xmem_erase(XMEM_ERASE_UNIT_SIZE, APP_NONCE_DATA);
	xmem_pwrite(&temp_buf[SEC_DATA_SIZE-1], 1, APP_NONCE_DATA+4);

	PRINTF("sec-arp: parse OK\n");

	return 1;
}
