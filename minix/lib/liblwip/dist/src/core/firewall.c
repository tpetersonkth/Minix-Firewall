//
// Created by davis on 2018-12-06.
//

#include "lwip/firewall.h"
#include "lwip/opt.h"
#include <minix/fwdec.h>

/*
 * Filter function for the firewall server
 * Extracts the IP, port and protocol of a pbuf
 * Sends the data to the fwdec server
 */
void pbuf_filter(struct pbuf *p)
{
  //TODO fill these variables with values
  int protocol = 11;
  int src_ip = 22;
  int dst_ip = 33;
  int src_port = 44;
  int dst_port = 55;

  //Ask firewall for advice through ipc message
  if (fwdec_check_packet(protocol, src_ip, dst_ip, src_port, dst_port) != LWIP_KEEP_PACKET){
      //Drop packet
      printf("Dropping packet\n");
      pbuf_free(p);
    }
  printf("Keeping packet\n");
}