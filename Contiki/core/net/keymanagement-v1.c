/*
 * keymanagement-v1.c
 *
 *  Created on: Jul 26, 2013
 *      Author: crea
 */

#include "keymanagement-v1.h"
#include "dev/cc2420.h"
#include "net/packetbuf.h"
#include "uip.h"

#define MAX_NONCES 2
#define DEVICE_NOT_FOUND -1

struct nonces {
  uip_ipaddr_t  *device_id;
  uint32_t 	 	src_msg_cntr;
  uint8_t 	 	src_nonce_cntr;
};

struct keymanagement_state {
	enum {IDLE, REQUEST_KEY, UPDATE_KEY} state;
};

static uint8_t  amount_of_known_devices;
static struct nonces received_nonces[MAX_NONCES];
static struct keymanagement_state *s;
uint32_t msg_cntr;

/*-----------------------------------------------------------------------------------*/
/**
 * Output function
 */
/*-----------------------------------------------------------------------------------*/
int
send_encrypted(uint8_t *data, uint8_t *data_len)
{
	uint8_t i;
	int dest_index;
	uint8_t nonce_ctr;

	/* Check the destination IPv6-address */
	dest_index = search_IP(...);

	if(dest_index < 0) {
		/* Not found request session key */
		s->state = REQUEST_KEY;
		return KEY_REQUEST_TX;
	}

	/* Read the nonce counter from Flash */
	xmem_pread(&nonce_ctr, 1, APP_SECURITY_DATA);

	/* Extend data packet with nonce */
	for(i=0; i < 4; i++) data[i] = (msg_cntr >> ((3-i)*8)) & 0xff;
	data[4] = nonce_ctr;

	*data_len = *data_len + 5;

	/* Encrypt message */
	if(!cc2420_encrypt_ccm(data, &nonce_ctr, data_len)) return ENCRYPT_FAILED;

	PRINTFSECAPP("after: ");
	for(i=1; i<22; i++) PRINTFSECAPP("%.2x",data[i]);
	PRINTFSECAPP("\n");

	return ENCRYPT_OK;
}

/*-----------------------------------------------------------------------------------*/
/**
 * Input function
 */
/*-----------------------------------------------------------------------------------*/
int
input_decrypt(uint8_t *data, uint8_t *data_len)
{
	uint32_t src_msg_cntr;
	uint8_t i;
	int src_index;

	/* Check if source address is known */
	src_index = search_IP(...);

	/* Parse message counter from source */
	for(i=0; i<4; i++) src_msg_cntr = (uint32_t)(data[i]<<((3-i)*8));

	/* Check if it is not a replay message */

	/* Decrypt message */
	cc2420_decrypt_ccm(data, &src_msg_cntr, &data[4], data_len);
}

/*-----------------------------------------------------------------------------------*/
/**
 * Search the given IP address
 */
/*-----------------------------------------------------------------------------------*/
int
search_IP(uip_ipaddr_t* curr_device_id)
{
	int index = DEVICE_NOT_FOUND;
	uint8_t i;

	for(i = 0; i < amount_of_known_devices; i++) {
		if(uip_ipaddr_cmp(curr_device_id , received_nonces[i].device_id)) {
			index = i;
			break;
		}
	}
	if(index == DEVICE_NOT_FOUND) {
		if(amount_of_known_devices < MAX_NONCES) {
			/* Add device to known devices */
			uip_ipaddr_copy(received_nonces[amount_of_known_devices].device_id, curr_device_id);
			index = amount_of_known_devices;
			amount_of_known_devices++;
		}
		else {
			PRINTFSECAPP("No space to add device\n");
		}
	}

	return index;
}
