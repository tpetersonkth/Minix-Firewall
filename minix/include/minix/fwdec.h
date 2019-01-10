/* Prototypes and definitions for FWDEC interface. */

#ifndef _MINIX_FWDEC_H
#define _MINIX_FWDEC_H

#include <sys/types.h>
#include <minix/endpoint.h>

/* fwdec.c */

/* U32 */
int fwdec_check_packet(int protocol, int src_ip, int dst_ip, int src_port, int dst_port, int tcp_syn, int tcp_ack);

#endif /* _MINIX_FWDEC_H */
