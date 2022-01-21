#ifndef CHKSUM_H
#define CHKSUM_H

#include<sys/types.h>

u_int16_t l4_sum(u_int16_t *buff, int words, u_int32_t *srcaddr, u_int32_t *dstaddr, u_int16_t proto, u_int16_t len);

#endif /* CHKSUM_H */
