/*
 * sec-arp-server.c
 *
 *  Created on: Sep 24, 2013
 *      Author: crea
 */

#include "net/sec-arp-server.h"
#include "net/uip-ds6.h"
#include "net/rime/rimeaddr.h"
#include "net/packetbuf.h"

#include "dev/slip.h"

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...) do {} while (0)
#endif

/*-----------------------------------------------------------------------------------*/
/**
 * Parse hello request packet
 *
 * format: | message_type(1) | operation(1) | device id(16)
 */
/*-----------------------------------------------------------------------------------*/
void
parse_hello_req(uint8_t *buf)
{
	uint8_t slip_buf[26];

	PRINTF("sec-arp: parse\n");

	if(buf[0] != HELLO_PACKET) {
		return;
	}

	if(buf[1] != SEC_ARP_REQUEST) {
		return;
	}

	/* Set message type for slip */
	slip_buf[0] = (uint8_t) SEC_MARKER;
	slip_buf[1] = (uint8_t) REQ_MSG;

	/* Extract src MAC-address */
	memcpy(&slip_buf[2], &packetbuf_addr(PACKETBUF_ADDR_SENDER)->u8[0], sizeof(rimeaddr_t));

	/* Copy message from packetbuf to slip_buf */
	memcpy(&slip_buf[10], &buf[2], HELLO_REQ_PACKETSIZE-2);

	/* If we have a valid request packet send over slip (to check database) */
	slip_write(slip_buf, 26);
}
