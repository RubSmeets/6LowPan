/*
 * keymanagement-v1.c
 *
 *  Created on: Jul 26, 2013
 *      Author: crea
 */

#include "symm-key-client-v1.h"
#include "dev/cc2420.h"
#include "net/packetbuf.h"

#include <string.h>

#if !(ENABLE_CBC_LINK_SECURITY & SEC_SERVER)

#define DEBUG_SEC 0
#if DEBUG_SEC
#include <stdio.h>
#define PRINTFSECKEY(...) printf(__VA_ARGS__)
#define PRINTFSECKEYM(...) printf(__VA_ARGS__)
#else
#define PRINTFSECKEY(...)
#define PRINTFSECKEYM(...)
#endif

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UDP_CLIENT_SEC_PORT 5446
#define UDP_SERVER_SEC_PORT 5444

//#define MAX_DEVICES 			3
#define DEVICE_NOT_FOUND 		-1
#define AUTHENTICATION_SUCCES	0x00

#define SEC_DATA_SIZE 			32
#define DEVICE_ID_SIZE			16
#define SEC_KEY_SIZE			16
#define KEY_NONCE_SIZE			4
#define NONCE_CNTR_SIZE			1
#define LENGTH_SIZE				1	/* To ensure that the data array stays inbounds */

#define SEC_KEY_OFFSET			16
#define ADATA_KEYEXCHANGE		4

#define CHECK_INTERVAL		(CLOCK_SECOND)*5
#define MAX_WAIT_TIME			2
#define MAX_SEND_TRIES			2

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

/* Different protocol message sizes */
#define INIT_REQUEST_MSG_SIZE	1	/* msg_type(1) */
#define INIT_REPLY_MSG_SIZE		4	/* msg_type(1) | req_nonce(3) */
#define COMM_REQUEST_MSG_SIZE	39	/* msg_type(1) | device_id(16) | remote_device_id(16) | req_nonce(3) | remote_req_nonce(3) */
#define COMM_REPLY_MSG_SIZE		46	/* encryption_nonce(3) | msg_type(1) | encrypted_req_nonce(3) | encrypted_sessionkey(16) | encrypted_remote_device_id(16) | MIC(8) */
#define VERIFY_REQUEST_MSG_SIZE	15	/* encryption_nonce(3) | msg_type(1) | encrypted_verify_nonce(3) | MIC(8) */
#define VERIFY_REPLY_MSG_SIZE	15	/* encryption_nonce(3) | msg_type(1) | encrypted_remote_verify_nonce(3) | MIC(8) */

/* Global variables */
struct device_sec_data devices[MAX_DEVICES];
static short state;
static short key_exchange_state;
static uint8_t key_exchange_idle_time;
static uint8_t send_tries;
static struct uip_udp_conn *sec_conn;
static uint8_t amount_of_known_devices;
static uint8_t curr_device_index;
static uip_ipaddr_t temp_remote_device_id;

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

/* Functions used in key management layer */
static int  search_device_id(uip_ipaddr_t* curr_device_id);
static int  add_device_id(uip_ipaddr_t* curr_device_id);
static void set_session_key_of_index(int index);
static uint8_t find_index_for_request(keyfreshness_flags_type_t search_option);
static void update_nonce(uint8_t index);
static uint8_t key_exchange_protocol(void);
static void send_key_exchange_packet(void);
static void init_reply_message(void);
static void comm_request_message(void);
static void verify_request_message(void);
static void verify_reply_message(void);
static short parse_packet(uint8_t *data, uint16_t len);
static uint8_t parse_comm_reply_message(uint8_t *data, uip_ipaddr_t *remote_device_id);
static void update_key_and_device_id(uint8_t *sessionkey);

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
static void
get_decrement_verify_nonce(uint8_t *temp_verify_nonce) {
	uint16_t temp_nonce = verify_nonce;

	if(verify_nonce_cntr == 0x00) {
		temp_verify_nonce[2] = 0xff;
		temp_nonce--;
	} else {
		temp_verify_nonce[2] = verify_nonce_cntr-1;
	}

	set16(temp_verify_nonce, 0, temp_nonce);
}
/*---------------------------------------------------------------------------*/
static void
reset_key_exchange_timer(void) {
	key_exchange_idle_time = 0;
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
	/* State to idle */
	state = S_IDLE;
	key_exchange_state = S_KEY_EXCHANGE_IDLE;

	request_nonce=1;
	verify_nonce=1;

	amount_of_known_devices = 1;

	PRINTFSECKEY("key_init Devices: %d\n", amount_of_known_devices);

	/* Start process */
	process_start(&keymanagement_process, NULL);
}

/*-----------------------------------------------------------------------------------*/
/**
 * Output function for the application layer to create and send an encrypted packet
 * over a specified udp_connection.
 *
 * @param the connection
 * @param the data to be encrypted
 * @param the data length of packet
 * @param the associated data (not encrypted but authenticated)
 * @param the remote ip-address
 * @param the remote udp-port
 * @return encrypt-flags																NIET GETEST!
 */
/*-----------------------------------------------------------------------------------*/
short
keymanagement_send_encrypted_packet(struct uip_udp_conn *c, uint8_t *data, uint8_t *data_len,
								unsigned short adata_len, uip_ipaddr_t *toaddr, uint16_t toport)
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
			PRINTFSECKEY("No space to add device. tot:%x max:%d\n", amount_of_known_devices, MAX_DEVICES);
			return NO_SPACE_FOR_DEVICE;
		} else {
			/* Request key for new device */
			PRINTFSECKEY("Requesting key for: %x at %d\n", toaddr->u8[0], amount_of_known_devices-1);
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
		devices[dest_index].key_freshness = FRESH;
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

	/* Set Associated data */
	adata_len = adata_len + NONCE_SIZE;

	/* Copy data to temp buf */
	memcpy(&tempbuf[NONCE_SIZE], data, *data_len);

	total_len = *data_len + NONCE_SIZE;

	PRINTFSECKEY("msg and nonce B: %d, %d\n", devices[dest_index].msg_cntr, devices[dest_index].nonce_cntr);

	/* Encrypt message */
	if(!cc2420_encrypt_ccm(tempbuf, &curr_ip->u8[0], &devices[dest_index].msg_cntr, &devices[dest_index].nonce_cntr, &total_len, adata_len)) return ENCRYPT_FAILED;

	/* Send packet over udp connection (Increment pointer by 1 to ignore length byte) */
	uip_udp_packet_sendto(c, &tempbuf[1], (int)total_len, toaddr, toport);

	/* Increment message counter if transmission successful!!!!!!!*/
	devices[dest_index].msg_cntr++;

	PRINTFSECKEY("msg and nonce A: %d, %d\n", devices[dest_index].msg_cntr, devices[dest_index].nonce_cntr);

	PRINTFSECKEYM("after: ");
	for(i=1; i<*data_len; i++) PRINTFSECKEYM("%.2x",tempbuf[i]);
	PRINTFSECKEYM("\n");

	return ENCRYPT_OK;
}

/*-----------------------------------------------------------------------------------*/
/**
 * Input function of application layer to decrypt messages
 *
 * @param source ip-address
 * @param the encrypted data
 * @param the packet length
 * @param the associated data
 * @return decrypt-flags																NIET GETEST!
 */
/*-----------------------------------------------------------------------------------*/
short
keymanagement_decrypt_packet(uip_ipaddr_t *remote_device_id, uint8_t *data, uint8_t *data_len, unsigned short adata_len)
{
	uint8_t src_nonce_cntr;
	uint8_t i;
	uint16_t src_msg_cntr = 0;

	int src_index;

	/* Check if source address is known */
	src_index = search_device_id(remote_device_id);

	if(src_index < 0) return DEVICE_NOT_FOUND_RX;

	/* Check if the key is fresh */
	if(devices[src_index].key_freshness == EXPIRED) return KEY_REQUEST_TX;

	/* Check nonce and message counter values */
	for(i=0; i < MSG_NONCE_SIZE; i++) src_msg_cntr |= ((uint16_t)data[i] << (((MSG_NONCE_SIZE-1)-i)*8));
	src_nonce_cntr = data[MSG_NONCE_SIZE];

	if((src_msg_cntr <= devices[src_index].remote_msg_cntr) || (src_nonce_cntr < devices[src_index].remote_nonce_cntr)) {
		PRINTFSECKEY("Replay message storeM: %d, recM: %d\n", devices[src_index].remote_msg_cntr, src_msg_cntr);
		return REPLAY_MESSAGE;
	}

	/* Get key for decryption */
	set_session_key_of_index(src_index);

	/* Decrypt message */
	if(!(cc2420_decrypt_ccm(data, &devices[src_index].remote_device_id.u8[0], &src_msg_cntr, &src_nonce_cntr, data_len, adata_len))) return DECRYPT_FAILED ;

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

			PRINTFSECKEY("key: state %x\n", state);

			/* Search for changes of nonce data */
			device_index = find_index_for_request(UPDATE_NONCE);
			if(device_index != MAX_DEVICES) {
				PRINTFSECKEY("key: update nonce\n");
				update_nonce(device_index);
			}

			/* Search for changes in security data */
			switch(state) {
				case S_IDLE:
					curr_device_index = find_index_for_request(EXPIRED);
					if(curr_device_index != MAX_DEVICES) {
						state = S_REQUEST_KEY;
						key_exchange_state = S_INIT_REQUEST;
					}
					break;

				case S_REQUEST_KEY:
					if(!(key_exchange_protocol())) state = S_IDLE;
					break;

				default:
					state = S_IDLE;
					break;
			}

			/* Increment key exchange timer */
			if(key_exchange_idle_time < MAX_WAIT_TIME) key_exchange_idle_time++;
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
search_device_id(uip_ipaddr_t *curr_device_id)
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
		/* Add device to known devices !!!!!!!!*/
		//uip_ipaddr_copy(&devices[amount_of_known_devices].remote_device_id, curr_device_id);
		memcpy(&devices[amount_of_known_devices].remote_device_id, curr_device_id, DEVICE_ID_SIZE);
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
	CC2420_WRITE_RAM_REV(&devices[index].session_key[0], CC2420RAM_KEY1, SEC_KEY_SIZE);
}

/*-----------------------------------------------------------------------------------*/
/**
 * Search for the index of device that wants to request a key or has
 * to update one.																			NIET GETEST!
 */
/*-----------------------------------------------------------------------------------*/
static uint8_t
find_index_for_request(keyfreshness_flags_type_t search_option)
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
 * Update nonce writes the new nonce of devices[index] to flash memory
 *
 * @param index of device																NIET GETEST!
 */
/*-----------------------------------------------------------------------------------*/
static void
update_nonce(uint8_t index)
{
	devices[index].key_freshness = FRESH;
}

/*-----------------------------------------------------------------------------------*/
/**
 *	Updates the session key and device id in the flash memory
 *
 *	@param current session-key															NIET AF!
 */
/*-----------------------------------------------------------------------------------*/
static void
update_key_and_device_id(uint8_t *sessionkey)
{

}

/*-----------------------------------------------------------------------------------*/
/**
 * key_exchange_protocol is the main callback (protocol) function that decides if the
 * protocol should continue or stop.
 *
 * @return stop/continue																	NIET AF!
 */
/*-----------------------------------------------------------------------------------*/
static uint8_t
key_exchange_protocol(void)
{
	/* Check if there is data to be processed */
	if(uip_newdata()) {
		PRINTFSECKEY("key: new data\n");
		/* Check if we have the right connection */
		if(uip_udp_conn->lport == UIP_HTONS(UDP_CLIENT_SEC_PORT)) {
			PRINTFSECKEY("key: right port\n");
			if(!(parse_packet((uint8_t *) uip_appdata, uip_datalen()))) return 0;
		}
	}
	PRINTFSECKEY("key: exchange state %d\n", key_exchange_state);
	/* Is there anything to send? */
	if(key_exchange_state == S_KEY_EXCHANGE_IDLE) return 0;

	/* Create and send protocol message */
	send_key_exchange_packet();

	uint8_t i;
	PRINTFSECKEY("key buf: ");
	for(i=0; i<tot_len; i++) PRINTFSECKEYM("%.2x",keypacketbuf[i]);
	PRINTFSECKEYM("\n");

	/* Increment send tries */
	if(send_tries > 4) 	send_tries = 0;
	else 				send_tries++;


	return 1;
}

/*-----------------------------------------------------------------------------------*/
/**
 * Key-exchange output function. Creates and sends a protocol message according
 * to the current state.
 */
/*-----------------------------------------------------------------------------------*/
static void
send_key_exchange_packet(void)
{
	keypacketbuf[0] = key_exchange_state;
	tot_len = 1;

	/* Check if still need to send */
	PRINTFSECKEY("key: send try %d\n", send_tries);
	if(send_tries >= MAX_SEND_TRIES) return;

	switch(key_exchange_state) {
		case S_INIT_REQUEST:
			/* Send packet to remote device */
			uip_udp_packet_sendto(sec_conn, keypacketbuf, tot_len, &temp_remote_device_id, UIP_HTONS(UDP_CLIENT_SEC_PORT));
			break;

		case S_INIT_REPLY:	/* | request_nonce(3) | */
			/* Create message */
			init_reply_message();
			/* Send packet to remote device */
			uip_udp_packet_sendto(sec_conn, keypacketbuf, tot_len, &temp_remote_device_id, UIP_HTONS(UDP_CLIENT_SEC_PORT));
			break;

		case S_COMM_REQUEST: /* | id curr(16) | id remote(16) | request_nonce(3) | remote request nonce(3) | */
			/* Create message */
			comm_request_message();
			/* Send packet to edge-router */
			uip_udp_packet_sendto(sec_conn, keypacketbuf, tot_len, &devices[0].remote_device_id, UIP_HTONS(UDP_SERVER_SEC_PORT));
			break;

		case S_VERIFY_REQUEST: /* | Ek{verify nonce} | */
			/* Create message */
			verify_request_message();
			/* Send encrypted packet to remote device */
			keymanagement_send_encrypted_packet(sec_conn, keypacketbuf, &tot_len, ADATA_KEYEXCHANGE,
													&devices[curr_device_index].remote_device_id, UIP_HTONS(UDP_CLIENT_SEC_PORT));
			break;

		case S_VERIFY_REPLY: /* | Ek{verify nonce-1} | */
			/* Create message */
			verify_reply_message();
			/* Send encrypted packet to remote device */
			keymanagement_send_encrypted_packet(sec_conn, keypacketbuf, &tot_len, ADATA_KEYEXCHANGE,
													&devices[curr_device_index].remote_device_id, UIP_HTONS(UDP_CLIENT_SEC_PORT));
			/* Switch to state IDLE */
			key_exchange_state = S_KEY_EXCHANGE_IDLE;
			break;

		default:
			break;
	}
}

/*-----------------------------------------------------------------------------------*/
/**
 *	Set keypacketbuf with init reply message							 					NIET AF!
 */
/*-----------------------------------------------------------------------------------*/
static void
init_reply_message(void) {
	set16(keypacketbuf, 1, request_nonce);
	keypacketbuf[3] = request_nonce_cntr;
	tot_len = 4;
}

/*-----------------------------------------------------------------------------------*/
/**
 *	Set keypacketbuf with communication request message										NIET GETEST
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
}

/*-----------------------------------------------------------------------------------*/
/**
 *	Set keypacketbuf with verify request message											NIET GETEST
 */
/*-----------------------------------------------------------------------------------*/
static void
verify_request_message(void)
{
	/* Copy verify nonce */
	set16(keypacketbuf, 1, verify_nonce);
	keypacketbuf[3] = verify_nonce_cntr;

	tot_len = 4;
}

/*-----------------------------------------------------------------------------------*/
/**
 *	Set keypacketbuf with verify reply message											NIET GETEST
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
 * The parse function dissects the incoming messages according to the
 * current state. It also serves as next-state function for the protocol.
 *
 * @param udp payload data
 * @param udp packet lenght
 * @return failed/successful
 *
 * After specific time every step has to return to key exchange idle!
 * 																							NIET AF!
 */
/*-----------------------------------------------------------------------------------*/
static short
parse_packet(uint8_t *data, uint16_t len)
{
	uint8_t temp_data_len = len & 0xff;
	uint8_t temp_verify_nonce[3];

	if((key_exchange_idle_time == MAX_WAIT_TIME) && (key_exchange_state != S_KEY_EXCHANGE_IDLE)) {
		key_exchange_state = S_KEY_EXCHANGE_IDLE;
		reset_key_exchange_timer();
		return 0;
	}

	switch(key_exchange_state) {
		case S_KEY_EXCHANGE_IDLE:
			if(data[0] == S_INIT_REQUEST && len == INIT_REQUEST_MSG_SIZE) {
				/*
				 * Check if the request has been send before to ensure that
				 * we don't waste resources on replay attacks
				 */
				//if(...) {

				/* Check if we know the source */
				if(search_device_id(&UIP_IP_BUF->srcipaddr) < 0) {
					/* If not -> check if there still is free space for new devices */
					if(amount_of_known_devices < MAX_DEVICES) {
						/* Copy requesting id */
						memcpy(&temp_remote_device_id.u8[0], &UIP_IP_BUF->srcipaddr.u8[0], DEVICE_ID_SIZE);
					} else {
						return 0;
					}
				}
				/* If there is a valid request we need to reply */
				key_exchange_state = S_INIT_REPLY;
				/* Send tries reset */
				send_tries = 0;
				/* Timer reset */
				reset_key_exchange_timer();

				//}
			}
			break;

		case S_INIT_REQUEST:
			if(data[0] == S_INIT_REPLY && len == INIT_REPLY_MSG_SIZE && send_tries > 0) {
				/* Get the remote nonce */
				memcpy(&remote_request_nonce[0], &data[1], 3);

				key_exchange_state = S_COMM_REQUEST;
				/* Send tries reset */
				send_tries = 0;
				/* Timer reset */
				reset_key_exchange_timer();
			}
			break;

		case S_INIT_REPLY:	   /* | request_nonce(3) | */
			if(data[3] == S_COMM_REPLY && len == COMM_REPLY_MSG_SIZE) {
				if(keymanagement_decrypt_packet(&UIP_IP_BUF->srcipaddr, data, &temp_data_len, ADATA_KEYEXCHANGE) == DECRYPT_OK) {
					/* Parse packet */
					if(parse_comm_reply_message(data, &temp_remote_device_id)) {
						/* Send verify message */
						key_exchange_state = S_VERIFY_REQUEST;
						/* Send tries reset */
						send_tries = 0;
						/* Timer reset */
						reset_key_exchange_timer();
					}
				}
			}
			break;

		case S_COMM_REQUEST:   /* | remote_decryption_nonce(3) | msg_type(1) | request_nonce(3) | sessionkey(16) | id remote(16) | MIC(8) | */
			if(data[3] == S_COMM_REPLY && len == COMM_REPLY_MSG_SIZE) {
				if(keymanagement_decrypt_packet(&UIP_IP_BUF->srcipaddr, data, &temp_data_len, ADATA_KEYEXCHANGE) == DECRYPT_OK) {
					/* Parse packet */
					if(parse_comm_reply_message(data, &devices[curr_device_index].remote_device_id)) {
						/* Wait for Verify message */
						key_exchange_state = S_COMM_REPLY;
						/* Send tries reset */
						send_tries = 0;
						/* Timer reset */
						reset_key_exchange_timer();
					}
				}
			}
			break;

		case S_COMM_REPLY:
			if(data[3] == S_VERIFY_REQUEST && len == VERIFY_REQUEST_MSG_SIZE && send_tries > 0) {
				if(keymanagement_decrypt_packet(&UIP_IP_BUF->srcipaddr, data, &temp_data_len, ADATA_KEYEXCHANGE) == DECRYPT_OK) {
					/* Store verify nonce */
					memcpy(&remote_verify_nonce[0], &data[4], 3);
					/* reply to verify message */
					key_exchange_state = S_VERIFY_REPLY;
					/* Send tries reset */
					send_tries = 0;
				}
			}
			break;

		case S_VERIFY_REQUEST: /* | Ek{verify nonce} | */
			if(data[3] == S_VERIFY_REPLY && len == VERIFY_REPLY_MSG_SIZE) {
				if(keymanagement_decrypt_packet(&UIP_IP_BUF->srcipaddr, data, &temp_data_len, ADATA_KEYEXCHANGE) == DECRYPT_OK) {
					/* Decrement verify request nonce */
					get_decrement_verify_nonce(temp_verify_nonce);

					/* Compare verify reply nonce */
					if(memcmp(&temp_verify_nonce[0], &data[4], 3) == 0) {
						/* Increment verify nonce */
						increment_verify_nonce();
						/* Go back to idle state */
						key_exchange_state = S_KEY_EXCHANGE_IDLE;
						/* Send tries reset */
						send_tries = 0;
					}
				}
			}
			break;

		default:
			break;
	}

	return 1;
}

/*-----------------------------------------------------------------------------------*/
/**
 *	Help function to parse the content of communication reply message.
 *
 *	@param pointer to data
 *	@param pointer to current device id
 *	@return failed/successful																NIET AF!
 */
/*-----------------------------------------------------------------------------------*/
#define REMOTE_ID_OFFSET		23
#define SESSIONKEY_OFFSET		7
#define REQUEST_NONCE_OFFSET	4

static uint8_t
parse_comm_reply_message(uint8_t *data, uip_ipaddr_t *remote_device_id) {
	uint8_t temp_request_nonce[3];

	/* Assemble request nonce */
	set16(temp_request_nonce, 0, request_nonce);
	temp_request_nonce[2] = request_nonce_cntr;

	/* Check request nonce */
	if(memcmp(&data[REQUEST_NONCE_OFFSET], &temp_request_nonce[0], 3) != 0) {
		/* Doesn't belong with current request - replay message */
		return 0;
	}

	/* Check remote device id */
	if(memcmp(&data[REMOTE_ID_OFFSET], &remote_device_id->u8[0], DEVICE_ID_SIZE) != 0) {
		/* Wrong remote id */
		return 0;
	}

	/* Add security device and data */
	if(key_exchange_state == S_INIT_REPLY) {
		curr_device_index = (uint8_t)add_device_id(remote_device_id);
	}
	devices[curr_device_index].nonce_cntr = 1;
	devices[curr_device_index].key_freshness = UPDATE_NONCE;

	/* Store security data */
	memcpy(&devices[curr_device_index].session_key[0], &data[SESSIONKEY_OFFSET], SEC_KEY_SIZE);

	/* Increment request nonce */
	increment_request_nonce();

	return 1;
}

#endif
