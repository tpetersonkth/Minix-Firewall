#ifndef _FWDEC_H_
#define _FWDEC_H_

#include <sys/types.h>
#include <minix/config.h>
#include <minix/ds.h>
#include <minix/bitmap.h>
#include <minix/param.h>
#include <regex.h>

#define FWDEC_DEBUG 1//Set to 1 to enable additional info on stdout

#define MODE_NOTSET 0
#define MODE_WHITELIST 1
#define MODE_BLACKLIST 2

/* Ip protocol definitions - Keep these numbers in sync with minix/lib/liblwip/dist/src/include/lwip/prot/ip.h*/
#define IP_PROTO_ICMP    1
#define IP_PROTO_IGMP    2
#define IP_PROTO_UDP     17
#define IP_PROTO_UDPLITE 136
#define IP_PROTO_TCP     6

struct Rule_s {//TODO: masking not yet used
    struct Rule_s* next;
    uint8_t proto;
    uint32_t srcIp;
    //uint8_t srcIpMask = 0;
    uint32_t  dstIp;
    //uint8_t dstIpMask = 0;
    uint16_t  srcPort;
    uint16_t  dstPort;
} RuleDefault = {0,0,0,0,0};
typedef struct Rule_s Rule;

#endif
