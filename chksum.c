#include "chksum.h"

#include <arpa/inet.h>

#include <stdint.h>
#include <stdio.h>

/*
 * TCP/UDP checksum function, RFC 768
 */
u_int16_t l4_sum(u_int16_t *buff, int words, u_int32_t *srcaddr, u_int32_t *dstaddr, u_int16_t proto, u_int16_t len)
{
	unsigned int last_word;

	/* Checksum enhancement - Support for odd byte packets */
	if((htons(len) % 2) == 1) {
		last_word = *((u_int8_t *)buff + ntohs(len) - 1);
		last_word = htons(last_word << 8);
	} else {
		/* Original checksum function */
		last_word = 0;
	}

	uint32_t sum = 0;
	for(int i = 0; i < words; i++){
		sum = sum + *(buff + i);
	}

	sum = sum + last_word;
    /* pseudo IPv4 header */
	sum = sum + (*(srcaddr) & 0xffff) + (*(srcaddr) >> 16) + (*(dstaddr) & 0xffff) + (*(dstaddr) >> 16) + proto + len;
    /* carry-out bits */
	sum = (sum >> 16) + sum;
	return ~sum;
}
