/*
 * Copyright (c) 2008, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *         AES encryption functions.
 * \author
 *         Adam Dunkels <adam@sics.se>
 */

#include "contiki.h"
#include "dev/cc2420.h"
#include "dev/cc2420-aes.h"
#include "dev/spi.h"

#include <string.h>

#define DEBUG_SEC 1
#if DEBUG_SEC
#include <stdio.h>
#define PRINTFSECAPP(...) printf(__VA_ARGS__)
#else
#define PRINTFSECAPP(...)
#endif

#define KEYLEN 16
#define MAX_DATALEN 16

#define CC2420_WRITE_RAM_REV(buffer,adr,count)               \
  do {                                                       \
    uint8_t i;                                               \
    CC2420_SPI_ENABLE();                                     \
    SPI_WRITE_FAST(0x80 | (adr & 0x7f));                     \
    SPI_WRITE_FAST((adr >> 1) & 0xc0);                       \
    for(i = (count); i > 0; i--) {                           \
      SPI_WRITE_FAST(((uint8_t*)(buffer))[i - 1]);           \
    }                                                        \
    SPI_WAITFORTx_ENDED();                                   \
    CC2420_SPI_DISABLE();                                    \
  } while(0)

#define MIN(a,b) ((a) < (b)? (a): (b))

#if ENABLE_CCM_APPLICATION
#include "net/rime.h"
#include "net/packetbuf.h"

#define MAX_NONCES 2

uint32_t msg_cntr;

struct nonces {
  rimeaddr_t sender;
  uint32_t 	 src_msg_cntr;
  uint8_t 	 src_nonce_cntr;
};

static uint8_t  amount_of_known_devices;
static struct nonces received_nonces[MAX_NONCES];

#endif

/*---------------------------------------------------------------------------*/
void
cc2420_aes_set_key(const uint8_t *key, int index)
{
  switch(index) {
  case 0:
    CC2420_WRITE_RAM_REV(key, CC2420RAM_KEY0, KEYLEN);
    break;
  case 1:
    CC2420_WRITE_RAM_REV(key, CC2420RAM_KEY1, KEYLEN);
    break;
  }
}
/*---------------------------------------------------------------------------*/
/* Encrypt at most 16 bytes of data. */
static void
cipher16(uint8_t *data, int len)
{
  uint8_t status;

  len = MIN(len, MAX_DATALEN);

  CC2420_WRITE_RAM(data, CC2420RAM_SABUF, len);
  CC2420_STROBE(CC2420_SAES);
  /* Wait for the encryption to finish */
  do {
    CC2420_GET_STATUS(status);
  } while(status & BV(CC2420_ENC_BUSY));
  CC2420_READ_RAM(data, CC2420RAM_SABUF, len);
}
/*---------------------------------------------------------------------------*/
void
cc2420_aes_cipher(uint8_t *data, int len, int key_index)
{
  int i;
  uint16_t secctrl0;

  CC2420_READ_REG(CC2420_SECCTRL0, secctrl0);

  secctrl0 &= ~(CC2420_SECCTRL0_SAKEYSEL0 | CC2420_SECCTRL0_SAKEYSEL1);

  switch(key_index) {
  case 0:
    secctrl0 |= CC2420_SECCTRL0_SAKEYSEL0;
    break;
  case 1:
    secctrl0 |= CC2420_SECCTRL0_SAKEYSEL1;
    break;
  }
  CC2420_WRITE_REG(CC2420_SECCTRL0, secctrl0);

  for(i = 0; i < len; i = i + MAX_DATALEN) {
    cipher16(data + i, MIN(len - i, MAX_DATALEN));
  }
}
/*---------------------------------------------------------------------------*/
#if ENABLE_CCM_APPLICATION
/*---------------------------------------------------------------------------*/
void
aes_ccm_message_encrypt(uint8_t *data, uint8_t *data_len)
{
	uint8_t nonce_ctr;

	/* Read the nonce counter from Flash */
	xmem_pread(&nonce_ctr, 1, APP_SECURITY_DATA);

	/* Extend data packet with nonce */
	uint8_t i;
	for(i=0; i < 4; i++) data[i] = (msg_cntr >> ((3-i)*8)) & 0xff;
	data[4] = nonce_ctr;

	*data_len = *data_len + 5;

	/* Encrypt message */
	if(!cc2420_encrypt_ccm(data, &nonce_ctr, data_len)) return;

	PRINTFSECAPP("after: ");
	for(i=1; i<22; i++) PRINTFSECAPP("%.2x",data[i]);
	PRINTFSECAPP("\n");
}
/*---------------------------------------------------------------------------*/
void
aes_ccm_message_decrypt(uint8_t *data, uint8_t *data_len)
{
	uint32_t src_msg_cntr;
	uint8_t i, src_index;

	/* Parse message counter from source */
	for(i=0; i<4; i++) src_msg_cntr = (uint32_t)(data[i]<<((3-i)*8));
	//src_msg_cntr = ((uint32_t)data[0]<<24) + ((uint32_t)data[1]<<16) + ((uint32_t)data[2]<<8) + (data[3]);

	/* Check if we know the source */ //VERHUIZEN NAAR KEYSCHEME LAYER
	src_index = 0xff;
	for(i = 0; i < amount_of_known_devices; i++) {
		if(rimeaddr_cmp(packetbuf_addr(PACKETBUF_ADDR_SENDER), &received_nonces[i].sender)) {
			src_index = i;
			break;
		}
	}
	if(src_index == 0xff) {
		if(amount_of_known_devices < MAX_NONCES) {
			/* Add device to known devices */
			rimeaddr_copy(&received_nonces[amount_of_known_devices].sender, packetbuf_addr(PACKETBUF_ADDR_SENDER));
			received_nonces[amount_of_known_devices].src_msg_cntr = src_msg_cntr;
			received_nonces[amount_of_known_devices].src_nonce_cntr = data[4];
			amount_of_known_devices++;
		}
		else {
			PRINTFSECAPP("No space to add device\n");
			return;
		}
	}

	/* Check if it is not a replay message */

	/* Decrypt message */
	cc2420_decrypt_ccm(data, &src_msg_cntr, &data[4], data_len);
}
/*---------------------------------------------------------------------------*/
#endif
