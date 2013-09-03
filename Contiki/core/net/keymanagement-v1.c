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

#define DEBUG_SEC 0
#if DEBUG_SEC
#include <stdio.h>
#define PRINTFSECKEY(...)
#define PRINTFSECKEYM(...) printf(__VA_ARGS__)
#else
#define PRINTFSECKEY(...)
#define PRINTFSECKEYM(...)
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

#define CHECK_INTERVAL		(CLOCK_SECOND)*5

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
static uint16_t keypacketbuf_aligned[(MAX_MESSAGE_SIZE) / 2 + 1];
static uint8_t *keypacketbuf = (uint8_t *)keypacketbuf_aligned;
static uint8_t tot_len;

/* Key exchange nonces */
static uint16_t request_nonce;
static uint16_t verify_nonce;
static keyExNonce_type_t request_nonce_cntr;
static keyExNonce_type_t verify_nonce_cntr;
static uint8_t remote_request_nonce[3];
static uint8_t remote_verify_nonce[3];
static uint8_t update_key_exchange_nonce;

static uint8_t amount_of_known_devices;
static uint8_t curr_device_index;

/* Functions used in key management layer */
static int  search_device_id(uip_ipaddr_t* curr_device_id);
static int  add_device_id(uip_ipaddr_t* curr_device_id);
static void set_session_key_of_index(int index);
static uint8_t find_index_of_request(keyfreshness_flags_type_t search_option);
static void update_nonce(uint8_t index);
static uint8_t key_exchange_protocol(void);
static void create_packet(void);
static void init_reply_message(void);
static void comm_request_message(void);
static void verify_request_message(void);
static void verify_reply_message(void);
static void send_packet(void);
static void parse_packet(uint8_t *data, uint16_t len);

/*---------------------------------------------------------------------------*/
PROCESS(keymanagement_process, "key management");
/*---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/
static uint16_t
get16(uint8_t *buffer, int pos)
{
  return (uint16_t)buffer[pos] << 8 | buffer[pos + 1];
}
/*---------------------------------------------------------------------------*/
static void
set16(uint8_t *buffer, int pos, uint16_t value)
{
  buffer[pos++] = value >> 8;
  buffer[pos++] = value & 0xff;
}
/*---------------------------------------------------------------------------*/
static void
increment_request_nonce(void) {
	if(request_nonce_cntr == 0xff) {
		request_nonce_cntr = 0;
		request_nonce++;
		update_key_exchange_nonce = 1;
	} else {
		request_nonce_cntr++;
	}
}
/*---------------------------------------------------------------------------*/
static void
increment_verify_nonce(void) {
	if(verify_nonce_cntr == 0xff) {
		verify_nonce_cntr = 0;
		verify_nonce++;
		update_key_exchange_nonce = 1;
	} else {
		verify_nonce_cntr++;
	}
}
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
	request_nonce = get16(temp_sec_nonce_list, 0);
	verify_nonce = get16(temp_sec_nonce_list, 2);

	/* Security trade-off (If nonce value overflows, replay attacks are easy) */
	request_nonce++;
	verify_nonce++;
	set16(temp_sec_nonce_list, 0, request_nonce);
	set16(temp_sec_nonce_list, 2, verify_nonce);

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
keymanagement_send_encrypted_packet(struct uip_udp_conn *c, uint8_t *data, uint8_t *data_len,
								uip_ipaddr_t *toaddr, uint16_t toport)
{
	uint8_t i, total_len;
	int dest_index;
	uip_ipaddr_t *curr_ip = NULL;
	uint8_t tempbuf[*data_len+APP_MIC_LEN+NONCE_SIZE+LENGTH_SIZE];

	/* Check the destination IPv6-address */
	if(uip_is_addr_unspecified(toaddr)) return ENCRYPT_FAILED;
	dest_index = search_device_id(toaddr);

	if(dest_index < 0) {
		/* try to add designated device */
		if(add_device_id(toaddr) < 0) {
			/* No space for device */
			PRINTFSECKEY("No space to add device. tot:%d max:%d\n", amount_of_known_devices, MAX_DEVICES);
			return NO_SPACE_FOR_DEVICE;
		} else {
			/* Request key for new device */
			PRINTFSECKEY("Requesting key for: %d at %d\n", toaddr->u8[0], amount_of_known_devices-1);
			devices[amount_of_known_devices-1].key_freshness = EXPIRED;
			return KEY_REQUEST_TX;
		}
	}

	/* Check if the key is still valid */
	if(devices[dest_index].key_freshness != FRESH) return KEY_REQUEST_TX;

	/* Check nonce counter value first */
	if(devices[dest_index].nonce_cntr == MAX_NONCE_COUNT) {
		/* Request new key */
		devices[dest_index].key_freshness = EXPIRED;
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
	uip_ds6_select_src(curr_ip, toaddr);

	PRINTFSECKEY("ipv6: ");
	for(i=1; i<16; i++) PRINTFSECKEY("%.2x ",curr_ip->u8[i]);
	PRINTFSECKEY("\n");

	/* Extend data packet with nonce */
	for(i=0; i < MSG_NONCE_SIZE; i++) tempbuf[i] = (devices[dest_index].msg_cntr >> (((MSG_NONCE_SIZE-1)-i)*8)) & 0xff;
	tempbuf[MSG_NONCE_SIZE] = devices[dest_index].nonce_cntr;

	/* Copy data to temp buf */
	memcpy(&tempbuf[NONCE_SIZE], data, *data_len);

	total_len = *data_len + NONCE_SIZE;

	PRINTFSECKEY("msg and nonce B: %ld, %d\n", devices[dest_index].msg_cntr, devices[dest_index].nonce_cntr);

	/* Encrypt message */
	if(!cc2420_encrypt_ccm(tempbuf, &curr_ip->u8[0], &devices[dest_index].msg_cntr, &devices[dest_index].nonce_cntr, &total_len)) return ENCRYPT_FAILED;

	/* Send packet over udp connection (Increment pointer by 1 to ignore length byte) */
	uip_udp_packet_sendto(c, &tempbuf[1], (int)total_len, toaddr, toport);

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
	if(devices[src_index].key_freshness == EXPIRED) return KEY_REQUEST_TX;

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

	/*
	 * new connection with remote host at port 0
	 * to allow multiple remote ports on the same
	 * connection
	 */
	sec_conn = udp_new(NULL, 0, NULL);
	if(sec_conn == NULL) {
	  PRINTFSECKEY("No UDP conn, exiting proc!\n");
	  PROCESS_EXIT();
	}
	udp_bind(sec_conn, UIP_HTONS(UDP_CLIENT_SEC_PORT));

	/* Periodic checking of state -> is the time overhead big????? or Event based checking-???? */
	etimer_set(&periodic, CHECK_INTERVAL);
	while(1) {
		PROCESS_YIELD();

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
					curr_device_index = find_index_of_request(EXPIRED);
					if(curr_device_index != MAX_DEVICES) state = S_REQUEST_KEY;
					break;

				case S_REQUEST_KEY:
					if(!(key_exchange_protocol())) state = S_IDLE;
					break;

				default:
					state = S_IDLE;
					break;
			}
		}

		if(ev == tcpip_event) {
			if(!(key_exchange_protocol())) 	state = S_IDLE;
			else 							state = S_REQUEST_KEY;
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

	if((search_option == UPDATE_NONCE) && (update_key_exchange_nonce == 1)) return MAX_DEVICES+1;
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
	if(index != (MAX_DEVICES+1)) {
		temp_sec_nonce_list[(index*NONCE_CNTR_SIZE)+KEY_NONCE_SIZE] = devices[index].nonce_cntr;
		/* Clear request */
		devices[index].key_freshness = FRESH;
	} else {
		set16(temp_sec_nonce_list, 0, request_nonce);
		set16(temp_sec_nonce_list, 2, verify_nonce);
		/* Clear request */
		update_key_exchange_nonce = 0;
	}

	/* Write back to flash memory */
	xmem_erase(XMEM_ERASE_UNIT_SIZE, APP_NONCE_DATA);
	xmem_pwrite(temp_sec_nonce_list, ((MAX_DEVICES * NONCE_CNTR_SIZE) + KEY_NONCE_SIZE), APP_NONCE_DATA);
}

/*-----------------------------------------------------------------------------------*/
/**
 * key_exchange_protocol is the output function for the key-exchange protocol					NIET AF!
 */
/*-----------------------------------------------------------------------------------*/
static uint8_t
key_exchange_protocol(void)
{
	if(uip_newdata()) {
		/* Check if we have the right connection */
		if(uip_udp_conn->lport == UIP_HTONS(UDP_CLIENT_SEC_PORT)) {
			parse_packet((uint8_t *) uip_appdata, uip_datalen());
		}
	}

	create_packet();
	send_packet();
}

/*-----------------------------------------------------------------------------------*/
/**
 * 					NIET AF!
 */
/*-----------------------------------------------------------------------------------*/
static void
create_packet(void)
{
	keypacketbuf[0] = key_exchange_state;
	tot_len = 1;

	switch(key_exchange_state) {
		case S_INIT_REPLY:	/* | request_nonce(3) | */
			init_reply_message();
			break;

		case S_COMM_REQUEST: /* | id curr(16) | id remote(16) | request_nonce(3) | remote request nonce(3) | */
			comm_request_message();
			break;

		case S_VERIFY_REQUEST: /* | Ek{verify nonce} | */
			verify_request_message();
			break;

		case S_VERIFY_REPLY:
			verify_reply_message();
			break;

		default:
			break;
	}
}

/*-----------------------------------------------------------------------------------*/
/**
 * 					NIET AF!
 */
/*-----------------------------------------------------------------------------------*/
static void
init_reply_message(void) {
	set16(keypacketbuf, 1, request_nonce);
	keypacketbuf[3] = request_nonce_cntr;
	tot_len = 4;

	/* Increment request nonce */
	increment_request_nonce();
}

/*-----------------------------------------------------------------------------------*/
/**
 *
 */
/*-----------------------------------------------------------------------------------*/
static void
comm_request_message(void) {
	uip_ipaddr_t *curr_ip = NULL;

	/* Get own ip address */
	uip_ds6_select_src(curr_ip, &devices[0].remote_device_id);

	/* Copy own ID */
	memcpy(&keypacketbuf[1], &curr_ip->u8[0], DEVICE_ID_SIZE);
	/* Copy remote ID */
	memcpy(&keypacketbuf[17], &devices[curr_device_index].remote_device_id.u8[0], DEVICE_ID_SIZE);
	/* Copy request nonce */
	set16(keypacketbuf, 33, request_nonce);
	keypacketbuf[35] = request_nonce_cntr;
	/* Copy remote request nonce */
	memcpy(&keypacketbuf[36], remote_request_nonce, 3);

	tot_len = 39;
	/* Increment request nonce */
	increment_request_nonce();
}

/*-----------------------------------------------------------------------------------*/
/**
 *
 */
/*-----------------------------------------------------------------------------------*/
static void
verify_request_message(void)
{
	/* Copy verify nonce */
	set16(keypacketbuf, 1, verify_nonce);
	keypacketbuf[3] = verify_nonce_cntr;

	tot_len = 4;
	/* Increment verify nonce */
	increment_verify_nonce();
}

/*-----------------------------------------------------------------------------------*/
/**
 *
 */
/*-----------------------------------------------------------------------------------*/
static void
verify_reply_message(void)
{
	uint16_t temp_rverify_nonce;

	/* Subtract 1 from the remote verify nonce */
	if(remote_verify_nonce[2] == 0) {
		temp_rverify_nonce = get16(remote_verify_nonce, 0);
		temp_rverify_nonce--;
		set16(remote_verify_nonce, 0, temp_rverify_nonce);
		remote_verify_nonce[2] = 0xff;
	} else {
		remote_verify_nonce[2]--;
	}

	/* Copy remote verify nonce */
	memcpy(&keypacketbuf[1], remote_verify_nonce, 3);

	tot_len = 4;
}

/*-----------------------------------------------------------------------------------*/
/**
 * 					NIET AF!
 */
/*-----------------------------------------------------------------------------------*/
static void
send_packet(void)
{
	if(key_exchange_state == S_INIT_REQUEST || key_exchange_state == S_INIT_REPLY) {
		/* Send packet to remote device */
		uip_udp_packet_sendto(sec_conn, keypacketbuf, tot_len, &devices[curr_device_index].remote_device_id, UIP_HTONS(UDP_CLIENT_SEC_PORT));
	}
	else if(key_exchange_state == S_COMM_REQUEST) {
		/* Send packet to edge router */
		uip_udp_packet_sendto(sec_conn, keypacketbuf, tot_len, &devices[0].remote_device_id, UIP_HTONS(UDP_SERVER_SEC_PORT));
	}
	else if(key_exchange_state == S_VERIFY_REQUEST || key_exchange_state == S_VERIFY_REPLY) {
		/* Encrypt packet with newly established session key and send to remote device */
		keymanagement_send_encrypted_packet(sec_conn, keypacketbuf, &tot_len, &devices[curr_device_index].remote_device_id, UIP_HTONS(UDP_CLIENT_SEC_PORT));
	}
}

/*-----------------------------------------------------------------------------------*/
/**
 * 					NIET AF!
 */
/*-----------------------------------------------------------------------------------*/
static void
parse_packet(uint8_t *data, uint16_t len)
{
	switch(key_exchange_state) {
		case S_KEY_EXCHANGE_IDLE:

			break;

		case S_INIT_REQUEST:
			break;

		case S_INIT_REPLY:	/* | request_nonce(3) | */
			break;

		case S_COMM_REQUEST: /* | id curr(16) | id remote(16) | request_nonce(3) | remote request nonce(3) | */
			break;

		case S_VERIFY_REQUEST: /* | Ek{verify nonce} | */
			break;

		case S_VERIFY_REPLY:
			break;

		default:
			break;
	}
}
