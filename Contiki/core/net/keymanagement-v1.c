/*
 * keymanagement-v1.c
 *
 *  Created on: Jul 26, 2013
 *      Author: crea
 */

#include "keymanagement-v1.h"
#include "dev/cc2420.h"
#include "net/packetbuf.h"

#include <string.h>

#define DEBUG_SEC 1
#if DEBUG_SEC
#include <stdio.h>
#define PRINTFSECKEY(...)
#define PRINTFSECKEYM(...) printf(__VA_ARGS__)
#else
#define PRINTFSECKEY(...)
#endif

#define UDP_CLIENT_SEC_PORT 5446
#define UDP_SERVER_SEC_PORT 5444

#define MAX_DEVICES 			2
#define DEVICE_NOT_FOUND 		-1
#define AUTHENTICATION_SUCCES	0x00

#define SEC_DATA_SIZE 			32
#define DEVICE_ID_SIZE			16
#define SEC_KEY_SIZE			16
#define KEY_NONCE_SIZE			4
#define NONCE_CNTR_SIZE			1
#define LENGTH_SIZE				1	/* To ensure that the data array stays inbounds */

#define SEC_KEY_OFFSET			16
#define NONCE_OFFSET			32



#define CHECK_INTERVAL		(CLOCK_SECOND)

/* Different states */
#define S_IDLE 			0
#define S_REQUEST_KEY	1
#define S_UPDATE_KEY	2

/* Different key exchange states */
#define S_INIT_REQUEST		0
#define S_INIT_REPLY		1
#define S_COMM_REQUEST		2
#define S_COMM_REPLY		3
#define S_VERIFY_REQUEST	4
#define S_VERIFY_REPLY		5
#define S_KEY_EXCHANGE_IDLE 6

struct device_sec_data {
  uip_ipaddr_t  	remote_device_id;
  msgnonce_type_t	msg_cntr;
  uint8_t			nonce_cntr;
  msgnonce_type_t 	remote_msg_cntr;
  uint8_t 	 		remote_nonce_cntr;
  uint8_t			key_freshness;
};

static struct device_sec_data devices[MAX_DEVICES];
static short state;
static short key_exchange_state;
static struct uip_udp_conn *sec_conn;

/* Buffer variables */
static uint8_t keypacketbuf[MAX_MESSAGE_SIZE];
static uint8_t tot_len;
static uint8_t dataptr;

/* Key exchange nonces */
static uint16_t request_nonce;
static uint16_t reply_nonce;
static keyExNonce_type_t request_nonce_cntr;
static keyExNonce_type_t reply_nonce_cntr;

static uint8_t amount_of_known_devices;

static int  search_device_id(uip_ipaddr_t* curr_device_id);
static int  add_device_id(uip_ipaddr_t* curr_device_id);
static void set_session_key_of_index(int index);
static uint8_t find_index_of_request(keyfreshness_flags_type_t search_option);
static void update_nonce(uint8_t index);
static void tcpip_handler(void);
static void key_exchange_create(void);

/*---------------------------------------------------------------------------*/
PROCESS(keymanagement_process, "key management");
/*---------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------------*/
/**
 * Initialization function																GETEST!
 */
/*-----------------------------------------------------------------------------------*/
void
keymanagement_init(void)
{
	uint8_t temp_sec_device_list[(MAX_DEVICES * SEC_DATA_SIZE)];
	uint8_t temp_sec_nonce_list[(MAX_DEVICES * NONCE_CNTR_SIZE) + KEY_NONCE_SIZE];
	uint8_t i;

	/* State to idle */
	state = S_IDLE;

	/* Read the security data from flash and populate device list and nonces */
	xmem_pread(temp_sec_nonce_list, ((MAX_DEVICES * NONCE_CNTR_SIZE) + KEY_NONCE_SIZE), APP_NONCE_DATA);
	xmem_pread(temp_sec_device_list, (MAX_DEVICES * SEC_DATA_SIZE), APP_SECURITY_DATA);

	/* Set key-exchange nonce counters and increment them */
	//for(i=0; i<(KEY_NONCE_SIZE/2); i++) request_nonce |= ((keyExNonce_type_t)temp_sec_nonce_list[i]<<((((KEY_NONCE_SIZE/2)-1)-i)*8));
	request_nonce = ((keyExNonce_type_t)temp_sec_nonce_list[0] << 8) | (keyExNonce_type_t)temp_sec_nonce_list[1];
	reply_nonce = ((keyExNonce_type_t)temp_sec_nonce_list[2] << 8) | (keyExNonce_type_t)temp_sec_nonce_list[3];

	/* Security trade-off (If nonce value overflows, replay attacks are easy) */
	request_nonce++;
	reply_nonce++;
	temp_sec_nonce_list[0] = (request_nonce >> 8) & 0xff;
	temp_sec_nonce_list[1] = request_nonce & 0xff;
	temp_sec_nonce_list[2] = (reply_nonce >> 8) & 0xff;
	temp_sec_nonce_list[3] = reply_nonce & 0xff;

	amount_of_known_devices = 0;
	for(i=0; i<MAX_DEVICES; i++) {
		/* Set device_id */
		memcpy(&devices[i].remote_device_id.u8[0], &temp_sec_device_list[(i*SEC_DATA_SIZE)], DEVICE_ID_SIZE);

		/* Set nonce counter (Must be equal or greater than 1) */
		devices[i].nonce_cntr = temp_sec_nonce_list[((i*NONCE_CNTR_SIZE)+KEY_NONCE_SIZE)];
		PRINTFSECKEY("key_init device: %d nonce: %d\n",devices[i].remote_device_id.u8[15],devices[i].nonce_cntr);

		/* Reset message counter */
		devices[i].msg_cntr = 0;

		/*
		 * Check if the nonce is empty else increment and add device. Because
		 * the nonce counter must be equal or greater than 1, we can verify
		 * that there still is useful information.
		 * The nonce is auto incremented every time the device resets this
		 * ensures that the nonce is never used twice.
		 * */
		if(devices[i].nonce_cntr != 0) {
			if(devices[i].nonce_cntr == 0xff) {
				/* Request new key */
				devices[i].key_freshness = EXPIRED;
				state = S_REQUEST_KEY;
			} else {
				/* Increment nonces to allow the key to stay fresh */
				devices[i].key_freshness = FRESH;
				devices[i].nonce_cntr++;
				temp_sec_nonce_list[((i*NONCE_CNTR_SIZE)+KEY_NONCE_SIZE)]++;
			}
			amount_of_known_devices++;
		}
	}

	PRINTFSECKEY("key_init Devices: %d\n", amount_of_known_devices);

	/* Write nonce counters back to flash */
	if(amount_of_known_devices > 0) {
		xmem_erase(XMEM_ERASE_UNIT_SIZE, APP_NONCE_DATA);
		xmem_pwrite(temp_sec_nonce_list, ((MAX_DEVICES * NONCE_CNTR_SIZE) + KEY_NONCE_SIZE), APP_NONCE_DATA);
	}

	/* Start process */
	process_start(&keymanagement_process, NULL);
}

/*-----------------------------------------------------------------------------------*/
/**
 * Output function																			NIET GETEST!
 */
/*-----------------------------------------------------------------------------------*/
short
keymanagement_creat_encrypted_packet(struct uip_udp_conn *c, uint8_t *data, uint8_t *data_len)
{
	uint8_t i;
	int dest_index;
	uip_ipaddr_t *curr_ip = NULL;
	uint8_t tempbuf[*data_len+APP_MIC_LEN+NONCE_SIZE+LENGTH_SIZE];

	/* Check the destination IPv6-address */
	if(uip_is_addr_unspecified(&c->ripaddr)) return ENCRYPT_FAILED;
	dest_index = search_device_id(&c->ripaddr);

	if(dest_index < 0) {
		/* try to add designated device */
		if(add_device_id(&c->ripaddr) < 0) {
			/* No space for device */
			PRINTFSECKEY("No space to add device. tot:%d max:%d\n", amount_of_known_devices, MAX_DEVICES);
			//state = S_IDLE;
			return NO_SPACE_FOR_DEVICE;
		} else {
			/* Request key for new device */
			PRINTFSECKEY("Requesting key for: %d at %d\n", c->ripaddr.u8[0], amount_of_known_devices-1);
			devices[amount_of_known_devices-1].key_freshness = EXPIRED;
			//state = S_REQUEST_KEY;
			return KEY_REQUEST_TX;
		}
	}

	/* Check if the key is still valid */
	if(devices[dest_index].key_freshness != FRESH) return KEY_REQUEST_TX;

	/* Check nonce counter value first */
	if(devices[dest_index].nonce_cntr == MAX_NONCE_COUNT) {
		/* Request new key */
		devices[dest_index].key_freshness = EXPIRED;
		//state = S_REQUEST_KEY;
		return KEY_REQUEST_TX;
	}

	/* Check the message counter value */
	if(devices[dest_index].msg_cntr == MAX_MESSAGE_COUNT) {
		/*
		 * Increment the nonce counter, reset message counter
		 * and inform the state machine that the nonce has
		 * to be updated in flash.
		 */
		devices[dest_index].nonce_cntr++;
		devices[dest_index].msg_cntr = 0;
		devices[dest_index].key_freshness = UPDATE_NONCE;
	}

	/* Get Session key from flash */
	set_session_key_of_index(dest_index);

	/* Get own ip address */
	uip_ds6_select_src(curr_ip, &c->ripaddr);

	PRINTFSECKEY("ipv6: ");
	for(i=1; i<16; i++) PRINTFSECKEY("%.2x ",curr_ip->u8[i]);
	PRINTFSECKEY("\n");

	/* Extend data packet with nonce */
	for(i=0; i < MSG_NONCE_SIZE; i++) tempbuf[i] = (devices[dest_index].msg_cntr >> (((MSG_NONCE_SIZE-1)-i)*8)) & 0xff;
	tempbuf[MSG_NONCE_SIZE] = devices[dest_index].nonce_cntr;

	/* Copy data to temp buf */
	memcpy(&tempbuf[NONCE_SIZE], data, *data_len);

	tot_len = *data_len + NONCE_SIZE;

	PRINTFSECKEY("msg and nonce B: %ld, %d\n", devices[dest_index].msg_cntr, devices[dest_index].nonce_cntr);

	/* Encrypt message */
	if(!cc2420_encrypt_ccm(tempbuf, &curr_ip->u8[0], &devices[dest_index].msg_cntr, &devices[dest_index].nonce_cntr, data_len)) return ENCRYPT_FAILED;

	/* Send packet over udp connection (Increment pointer by 1 to ignore length byte) */


	/* Increment message counter if transmission successful!!!!!!!*/
	devices[dest_index].msg_cntr++;

	PRINTFSECKEY("msg and nonce A: %ld, %d\n", devices[dest_index].msg_cntr, devices[dest_index].nonce_cntr);

	PRINTFSECKEYM("after: ");
	for(i=1; i<*data_len; i++) PRINTFSECKEYM("%.2x",tempbuf[i]);
	PRINTFSECKEYM("\n");

	return ENCRYPT_OK;
}

/*-----------------------------------------------------------------------------------*/
/**
 * Input function																			NIET GETEST!
 */
/*-----------------------------------------------------------------------------------*/
short
keymanagement_decrypt_packet(struct uip_udp_conn *c, uint8_t *data, uint8_t *data_len)
{
	uint8_t src_nonce_cntr;
	uint8_t i;
	msgnonce_type_t src_msg_cntr = 0;

	int src_index;

	/* Check if source address is known !!!!!!!!!!!!!!*/
	src_index = search_device_id(&c->ripaddr);

	if(src_index < 0) return DEVICE_NOT_FOUND_RX;

	/* Check if the key is fresh */
	if(devices[src_index].key_freshness != FRESH) return KEY_REQUEST_TX;

	/* Check nonce and message counter values */
	for(i=0; i < MSG_NONCE_SIZE; i++) src_msg_cntr |= ((msgnonce_type_t)data[i] << (((MSG_NONCE_SIZE-1)-i)*8));
	src_nonce_cntr = data[MSG_NONCE_SIZE];

	if((src_msg_cntr <= devices[src_index].remote_msg_cntr) || (src_nonce_cntr < devices[src_index].remote_nonce_cntr)) {
		PRINTFSECKEY("Replay message storeM: %ld, recM: %ld\n", devices[src_index].remote_msg_cntr, src_msg_cntr);
		return REPLAY_MESSAGE;
	}

	/* Get key for decryption */
	set_session_key_of_index(src_index);

	/* Decrypt message */
	if(!(cc2420_decrypt_ccm(data, &devices[src_index].remote_device_id.u8[0], &src_msg_cntr, &src_nonce_cntr, data_len))) return DECRYPT_FAILED ;

	/* Check if authentication was successful */
	if(data[*data_len-1] != AUTHENTICATION_SUCCES) return AUTHENTICATION_FAILED;

	/* Store new values in security data */
	devices[src_index].remote_msg_cntr = src_msg_cntr;
	devices[src_index].remote_nonce_cntr = src_nonce_cntr;

	return DECRYPT_OK;
}

/*-----------------------------------------------------------------------------------*/
/**
 * Key management process																	NIET AF!
 */
/*-----------------------------------------------------------------------------------*/
PROCESS_THREAD(keymanagement_process, ev, data)
{
	static struct etimer periodic;
	uint8_t device_index;

	PROCESS_BEGIN();

	PRINTFSECKEY("keymanagement_process: started\n");

	/* new connection with remote host */
	sec_conn = udp_new(NULL, UIP_HTONS(UDP_SERVER_SEC_PORT), NULL);
	if(sec_conn == NULL) {
	  PRINTFSECKEY("No UDP conn, exiting proc!\n");
	  PROCESS_EXIT();
	}
	udp_bind(sec_conn, UIP_HTONS(UDP_CLIENT_SEC_PORT));

	/* Periodic checking of state -> is the time overhead big????? or Event based checking-???? */
	etimer_set(&periodic, CHECK_INTERVAL);
	while(1) {
		PROCESS_YIELD();
		if(ev == tcpip_event) {
		  //tcpip_handler();
		}

		if(etimer_expired(&periodic)) {
			etimer_reset(&periodic);

			/* Search for changes of nonce data */
			device_index = find_index_of_request(UPDATE_NONCE);
			if(device_index != MAX_DEVICES) {
				update_nonce(device_index);
			}

			/* Search for changes in security data */
			switch(state) {
				case S_IDLE:
					device_index = find_index_of_request(EXPIRED);
					if(device_index != MAX_DEVICES) state = S_REQUEST_KEY;
					break;

				case S_REQUEST_KEY:
					key_exchange_create();
					break;

				default:
					state = S_IDLE;
					break;
			}

		}
	}

	PROCESS_END();
}

/*-----------------------------------------------------------------------------------*/
/**
 * Search the given IP address																NIET GETEST!
 */
/*-----------------------------------------------------------------------------------*/
static int
search_device_id(uip_ipaddr_t* curr_device_id)
{
	int index = DEVICE_NOT_FOUND;
	uint8_t i;

	for(i = 0; i < amount_of_known_devices; i++) {
		if(memcmp(&curr_device_id->u8[0], &devices[i].remote_device_id.u8[0], DEVICE_ID_SIZE) == 0) {
			index = i;
			break;
		}
	}
	return index;
}

/*-----------------------------------------------------------------------------------*/
/**
 * add the given device id to secured communication											NIET GETEST!
 */
/*-----------------------------------------------------------------------------------*/
static int
add_device_id(uip_ipaddr_t* curr_device_id)
{
	int index = DEVICE_NOT_FOUND;

	if(amount_of_known_devices < MAX_DEVICES) {
		/* Add device to known devices */
		uip_ipaddr_copy(&devices[amount_of_known_devices].remote_device_id, curr_device_id);
		index = amount_of_known_devices;
		amount_of_known_devices++;
	}

	return index;
}

/*-----------------------------------------------------------------------------------*/
/**
 * Get the security data from flash for device at a given index (index)						NIET GETEST!
 */
/*-----------------------------------------------------------------------------------*/
static void
set_session_key_of_index(int index)
{
	uint8_t temp_sec_data[SEC_KEY_SIZE];

	/* Read Session key from flash memory */
	xmem_pread(temp_sec_data, SEC_KEY_SIZE, (APP_SECURITY_DATA+(index*SEC_DATA_SIZE)+SEC_KEY_OFFSET));

	/* Set the application session key */
	CC2420_WRITE_RAM_REV(&temp_sec_data[0], CC2420RAM_KEY1, SEC_KEY_SIZE);
}

/*-----------------------------------------------------------------------------------*/
/**
 * Search for the index of device that wants to request a key or has
 * to update one.																			NIET GETEST!
 */
/*-----------------------------------------------------------------------------------*/
static uint8_t
find_index_of_request(keyfreshness_flags_type_t search_option)
{
	uint8_t i;
	for(i=0; i<amount_of_known_devices; i++) {
		if(devices[i].key_freshness == search_option) {
			return i;
		}
	}

	return MAX_DEVICES;
}

/*-----------------------------------------------------------------------------------*/
/**
 * Update nonce writes the new nonce of devices[index] to flash memory						NIET GETEST!
 */
/*-----------------------------------------------------------------------------------*/
static void
update_nonce(uint8_t index)
{
	uint8_t temp_sec_nonce_list[(MAX_DEVICES * NONCE_CNTR_SIZE) + KEY_NONCE_SIZE];

	/* Read the security data from flash and populate device list */
	xmem_pread(temp_sec_nonce_list, ((MAX_DEVICES * NONCE_CNTR_SIZE) + KEY_NONCE_SIZE), APP_NONCE_DATA);

	/* Update nonce */
	temp_sec_nonce_list[(index*NONCE_CNTR_SIZE)+KEY_NONCE_SIZE] = devices[index].nonce_cntr;

	/* Write back to flash memory */
	xmem_erase(XMEM_ERASE_UNIT_SIZE, APP_NONCE_DATA);
	xmem_pwrite(temp_sec_nonce_list, ((MAX_DEVICES * NONCE_CNTR_SIZE) + KEY_NONCE_SIZE), APP_NONCE_DATA);
}

/*-----------------------------------------------------------------------------------*/
/**
 * tcpip_handler is the callback function for a tcpip event									NIET AF!
 */
/*-----------------------------------------------------------------------------------*/
static void
tcpip_handler(void)
{
	switch(state) {
		case S_IDLE:

			break;
		default:

			break;
	}
}

/*-----------------------------------------------------------------------------------*/
/**
 * key_exchange_create is the output function for the key-exchange protocol					NIET AF!
 */
/*-----------------------------------------------------------------------------------*/
static void
key_exchange_create(void)
{
	switch(key_exchange_state) {
		case S_KEY_EXCHANGE_IDLE:
			break;

		case S_INIT_REQUEST:
			break;

		case S_INIT_REPLY:
			break;

		case S_COMM_REQUEST:
			break;

		case S_COMM_REPLY:
			break;

		case S_VERIFY_REQUEST:
			break;

		case S_VERIFY_REPLY:
			break;

		default:
			key_exchange_state = S_KEY_EXCHANGE_IDLE;
			break;
	}
}
