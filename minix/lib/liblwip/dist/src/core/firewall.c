#include "lwip/firewall.h"
#include "lwip/opt.h"
#include <minix/fwdec.h>

/*
 * Filter function for the firewall server
 * Extracts the IP, port and protocol of a pbuf
 * Sends the data to the fwdec server
 */
int pbuf_filter (struct pbuf *p)
{
  void *data;
  data = p->payload;
  int *payload = data;
  unsigned int hlen = (*payload) & 0xF;
  unsigned int srcprt = *(payload + hlen) & 0xFF;
  unsigned int srcprt2 = *(payload + hlen) >> 8 & 0xFF;
  unsigned int dstprt = *(payload + hlen) >> 16 & 0xFF;
  unsigned int dstprt2 = *(payload + hlen) >> 24 & 0xFF;
  unsigned int flags = *(payload + hlen + 3) >> 8 & 0x3F;
  unsigned int synFlag = flags >> 1 & 0x1;
  unsigned int ackFlag = flags >> 4 & 0x1;
  unsigned int proto = (*(payload + 2) & 0xFF00) >> 8;
  unsigned int srcIp = *(payload + 3);
  unsigned int dstIp = *(payload + 4);

  dstprt = (dstprt << 4) + dstprt2;
  srcprt = (srcprt << 4) + srcprt2;

  dstIp = ((dstIp >> 24) & 0xFF) | ((dstIp << 8) & 0xFF0000) | ((dstIp >> 8) & 0xff00) | ((dstIp << 24) & 0xFF000000);
  srcIp = ((srcIp >> 24) & 0xFF) | ((srcIp << 8) & 0xFF0000) | ((srcIp >> 8) & 0xff00) | ((srcIp << 24) & 0xFF000000);

  int protocol = proto;
  int src_ip = srcIp;
  int dst_ip = dstIp;
  int src_port = srcprt;
  int dst_port = dstprt;

  // Ask firewall for advice through ipc message
  if (fwdec_check_packet (protocol, src_ip, dst_ip, src_port, dst_port, synFlag, ackFlag) != LWIP_KEEP_PACKET)
    {
      // Drop packet
      return LWIP_DROP_PACKET;
    }
  // Keep the packet
  return LWIP_KEEP_PACKET;
}
