#include "chksum.h"
#include "dhcp_err.h"

#include <arpa/inet.h>

#include <stdio.h>

int main(void) {
  uint32_t srcaddr = 0x0;
  uint32_t dstaddr = 0xffffffff;
  
  printf("0x%X\n", l4_sum((u_int16_t*)&pkt410[0], sizeof(pkt410) / 2, &srcaddr, &dstaddr, htons(17), htons(sizeof(pkt410))));
  return 0;
}
