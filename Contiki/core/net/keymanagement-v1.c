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
#define PRINTFSECKEY(...) printf(__VA_ARGS__)
#else
#define PRINTFSECKEY(...)
#endif

#define UDP_CLIENT_SEC_PORT 5446
#define UDP_SERVER_SEC_PORT 5444

#define MAX_DEVICES 			2
#define DEVICE_NOT_FOUND 		-1
#define SEC_DATA_SIZE 			33
#define DEVICE_ID_SIZE			16
#define SEC_KEY_SIZE			16
#define NONCE_OFFSET			32
#define NONCE_COUNTER_SIZE		5
#define LENGTH_SIZE				1	/* To ensure that the data array stays inbounds */
#define AUTHENTICATION_SUCCES	0x00

#define CHECK_INTERVAL		(CLOCK_SECOND)

/* Different states */
#define S_IDLE 			0
#define S_REQUEST_KEY	1
#define S_UPDATE_KEY	2

struct device_sec_data {
  uip_ipaddr_t  remote_device_id;
  uint32_t		msg_cntr;
  uint8_t		nonce_cntr;
  uint32_t 	 	remote_msg_cntr;
  uint8_t 	 	remote_nonce_cntr;
  uint8_t		key_freshness;
};

static struct device_sec_data devices[MAX_DEVICES];
static short state;
static struct uip_udp_conn *sec_conn;

/* Buffer variables */
static uint8_t keypacketbuf[MAX_MESSAGE_SIZE];
static uint8_t tot_len;
static uint8_t dataptr;

static uint8_t amount_of_known_devices;
static int stored_dest_index;

static int  search_device_id(uip_ipaddr_t* curr_device_id);
static int  add_device_id(uip_ipaddr_t* curr_device_id);
static void set_session_key_of_index(int index);
static uint8_t find_index_of_request(keyfreshness_flags_type_t search_option);
static void update_nonce(uint8_t index);
static void tcpip_handler(void);

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
	uint8_t temp_sec_device_list[MAX_DEVICES * SEC_DATA_SIZE];
	uint8_t i;

	/* State to idle */
	state = S_IDLE;

	/* Reset index (a value that never occurs)*/
	stored_dest_index = MAX_DEVICES;

	/* Read the security data from flash and populate device list */
	xmem_pread(temp_sec_device_list, (MAX_DEVICES * SEC_DATA_SIZE), APP_SECURITY_DATA);

	amount_of_known_devices = 0;
	for(i=0; i<MAX_DEVICES; i++) {
		/* Set device_id */
		memcpy(&devices[i].remote_device_id.u8[0], &temp_sec_device_list[i*SEC_DATA_SIZE], DEVICE_ID_SIZE);

		/* Set nonce counter (Must be equal or greater than 1) */
		devices[i].nonce_cntr = temp_sec_device_list[(i*SEC_DATA_SIZE)+NONCE_OFFSET];
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
				temp_sec_device_list[(i*SEC_DATA_SIZE)+NONCE_OFFSET]++;
			}
			amount_of_known_devices++;
		}
	}

	PRINTFSECKEY("key_init Devices: %d\n", amount_of_known_devices);

	/* Write nonce counter back to flash */
	if(amount_of_known_devices > 0) {
		xmem_erase(XMEM_ERASE_UNIT_SIZE, APP_SECURITY_DATA);
		xmem_pwrite(temp_sec_device_list, (MAX_DEVICES * SEC_DATA_SIZE), APP_SECURITY_DATA);
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
	uip_ds6_addr_t *curr_ip;
	uint8_t tempbuf[*data_len+APP_MIC_LEN+NONCE_COUNTER_SIZE+LENGTH_SIZE];

	/* Check the destination IPv6-address */
	//if(uip_is_addr_unspecified(&c->ripaddr)) return ENCRYPT_FAILED;
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

	/* Get Session key from flash if necessary */
	if(stored_dest_index != dest_index) {
		/* Read the Session key from Flash */
		set_session_key_of_index(dest_index);
		stored_dest_index = dest_index;
	}

	/* Get own ip address !!!!!!!!!!!*/
	curr_ip = uip_ds6_get_link_local(ADDR_TENTATIVE);

	PRINTFSECKEY("ipv6: ");
	//for(i=1; i<16; i++) PRINTFSECKEY("%.2x ",curr_ip->ipaddr.u8[i]);
	for(i=1; i<16; i++) PRINTFSECKEY("%.2x ",c->ripaddr.u8[i]);
	PRINTFSECKEY("\n");

	/* Extend data packet with nonce */
	for(i=0; i < 4; i++) tempbuf[i] = (devices[dest_index].msg_cntr >> ((3-i)*8)) & 0xff;
	tempbuf[4] = devices[dest_index].nonce_cntr;

	/* Copy data to temp buf */
	memcpy(&tempbuf[NONCE_COUNTER_SIZE], data, *data_len);

	tot_len = *data_len + NONCE_COUNTER_SIZE;

	PRINTFSECKEY("msg and nonce B: %ld, %d\n", devices[dest_index].msg_cntr, devices[dest_index].nonce_cntr);

	/* Encrypt message */
	//if(!cc2420_encrypt_ccm(tempbuf, &curr_ip->ipaddr.u8[0], &devices[dest_index].msg_cntr, &devices[dest_index].nonce_cntr, data_len)) return ENCRYPT_FAILED;
	if(!cc2420_encrypt_ccm(tempbuf, &c->ripaddr.u8[0], &devices[dest_index].msg_cntr, &devices[dest_index].nonce_cntr, data_len)) return ENCRYPT_FAILED;

	/* Increment pointer by 1 to ignore length byte */
	data++;

	/* Send packet over udp connection */


	/* Increment message counter if transmission successful!!!!!!!*/
	devices[dest_index].msg_cntr++;

	PRINTFSECKEY("msg and nonce A: %ld, %d\n", devices[dest_index].msg_cntr, devices[dest_index].nonce_cntr);

	PRINTFSECKEY("after: ");
	for(i=1; i<22; i++) PRINTFSECKEY("%.2x",data[i]);
	PRINTFSECKEY("\n");

	return ENCRYPT_OK;
}

/*-----------------------------------------------------------------------------------*/
/**
 * Input function																			NIET AF!
 */
/*-----------------------------------------------------------------------------------*/
short
keymanagement_decrypt_packet(struct uip_udp_conn *c, uint8_t *data, uint8_t *data_len)
{
	uint8_t i, src_nonce_cntr;
	uint32_t src_msg_cntr;

	int src_index;

	/* Check if source address is known !!!!!!!!!!!!!!*/
	src_index = search_device_id(&c->ripaddr);

	if(src_index < 0) return DEVICE_NOT_FOUND_RX;

	/* Check if the key is fresh */
	if(devices[src_index].key_freshness != FRESH) return KEY_REQUEST_TX;

	/* Check nonce and message counter values */
	src_msg_cntr = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
	src_nonce_cntr = data[4];

	if((src_msg_cntr <= devices[src_index].remote_msg_cntr) || (src_nonce_cntr < devices[src_index].nonce_cntr)) {
		PRINTFSECKEY("Replay message storeM: %ld, recM: %ld\n", devices[src_index].remote_msg_cntr, src_msg_cntr);
		return REPLAY_MESSAGE;
	}

	/* Decrypt message */
	if(!(cc2420_decrypt_ccm(data, &devices[src_index].remote_device_id.u8[0], &src_msg_cntr, &src_nonce_cntr, data_len))) return DECRYPT_FAILED ;

	/* Check if authentication was successful */
	if(data[*data_len-1] == AUTHENTICATION_SUCCES) {

	}

	/* Store new values in security data */
	devices[src_index].remote_msg_cntr = src_msg_cntr;

	if(src_nonce_cntr > devices[src_index].nonce_cntr) {

	}

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

	/* Periodic checking of state */
	etimer_set(&periodic, CHECK_INTERVAL);
	while(1) {
		PROCESS_YIELD();
		if(ev == tcpip_event) {
		  //tcpip_handler();
		}

		if(etimer_expired(&periodic)) {
			etimer_reset(&periodic);
			/* Search for changes of security data */
			device_index = find_index_of_request(UPDATE_NONCE);
			if(device_index < MAX_DEVICES) {
				update_nonce(device_index);
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
	xmem_pread(temp_sec_data, SEC_KEY_SIZE, (APP_SECURITY_DATA+(index*SEC_DATA_SIZE)+SEC_KEY_SIZE));

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
	uint8_t temp_sec_device_list[MAX_DEVICES * SEC_DATA_SIZE];

	/* Read the security data from flash and populate device list */
	xmem_pread(temp_sec_device_list, (MAX_DEVICES * SEC_DATA_SIZE), APP_SECURITY_DATA);

	/* Update nonce */
	temp_sec_device_list[(index*SEC_DATA_SIZE)+NONCE_OFFSET] = devices[index].nonce_cntr;

	/* Write back to flash memory */
	xmem_erase(XMEM_ERASE_UNIT_SIZE, APP_SECURITY_DATA);
	xmem_pwrite(temp_sec_device_list, (MAX_DEVICES * SEC_DATA_SIZE), APP_SECURITY_DATA);
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
