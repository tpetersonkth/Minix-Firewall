#ifndef _FWDEC_H_
#define _FWDEC_H_

#include <sys/types.h>
#include <minix/config.h>
#include <minix/ds.h>
#include <minix/bitmap.h>
#include <minix/param.h>
#include <regex.h>

#define FWDEC_DEBUG 0//Set to 1 to enable additional info on stdout, 0 to disable

#define MODE_NOTSET 0
#define MODE_WHITELIST 1
#define MODE_BLACKLIST 2

/* Ip protocol definitions - Keep these numbers in sync with minix/lib/liblwip/dist/src/include/lwip/prot/ip.h*/
#define IP_PROTO_ICMP    1
#define IP_PROTO_IGMP    2
#define IP_PROTO_UDP     17
#define IP_PROTO_UDPLITE 136
#define IP_PROTO_TCP     6

struct Rule_s {
  struct Rule_s *next;
  uint8_t proto;
  uint32_t srcIp;
  uint32_t dstIp;
  uint16_t srcPort;
  uint16_t dstPort;
} RuleDefault = {0, 0, 0, 0, 0};
typedef struct Rule_s Rule;

struct tcpSynProt_s {//Used for keeping track of syn-scan and syn dos attacks
  struct tcpSynProt_s *next;
  uint32_t srcIp;
  uint32_t synCount;//The number of TCP syn packets recieved without subsequent ACK packets
  time_t timestamp;
};
typedef struct tcpSynProt_s tcpSynProt;

#endif
