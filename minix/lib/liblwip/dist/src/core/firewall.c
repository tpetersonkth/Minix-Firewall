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
  void *data;
  data = p->payload;
  int * payload = data;
  //unsigned char bytes[4];
  //printf("start\n");
  unsigned int hlen = (*payload) & 0xF;
  unsigned int srcprt =*(payload+hlen) & 0xFF;
  unsigned int srcprt2 =*(payload+hlen)>>8 & 0xFF;
  unsigned int dstprt =*(payload+hlen)>>16 & 0xFF;
  unsigned int dstprt2 =*(payload+hlen)>>24 & 0xFF;
 
  unsigned int proto = (*(payload + 2)& 0xFF00)>>8;
  printf("protcol: %d\n",proto);
  unsigned int srcIp = *(payload + 3);
  unsigned int dstIp = *(payload + 4);
  dstprt = (dstprt<<4) +dstprt2;
  srcprt = (srcprt<<4) +srcprt2;
  //printf("srcprt:%d,dstprt%d\n",srcprt,dstprt);
  dstIp =((dstIp>>24)&0xFF)|((dstIp<<8)&0xFF0000)|((dstIp>>8)&0xff00)|((dstIp<<24)&0xFF000000);
    /*  bytes[3] = *(&dstIp)  & 0xFF;
        bytes[2] = *(&dstIp)>>8 & 0xFF;
        bytes[1] = *(&dstIp)>>16 & 0xFF;
        bytes[0] = *(&dstIp)>>24 & 0xFF;
	printf("%d.%d.%d.%d intval: %d\n",bytes[3],bytes[2],bytes[1],bytes[0],dstIp);
    */
   srcIp =((srcIp>>24)&0xFF)|((srcIp<<8)&0xFF0000)|((srcIp>>8)&0xff00)|((srcIp<<24)&0xFF000000);
     /*   bytes[3] = *(&srcIp)  & 0xFF;
        bytes[2] = *(&srcIp)>>8 & 0xFF;
        bytes[1] = *(&srcIp)>>16 & 0xFF;
        bytes[0] = *(&srcIp)>>24 & 0xFF;
	printf("%d.%d.%d.%d intval: %d\n",bytes[3],bytes[2],bytes[1],bytes[0],srcIp);
     */
  /*printf("ipheader length:%d,srcprt:%d,dstprt:%d, \n",hlen,srcprt*16+srcprt2,dstprt*16+dstprt2);
  printf("pointer + hlen = %p, pointer = %p\n",(void *) (payload+hlen),(void *) (payload));
  for(int i= 0;i<6;){
        bytes[3] = *(payload + i) & 0xFF;
        bytes[2] = *(payload + i)>>8 & 0xFF;
        bytes[1] = *(payload + i)>>16 & 0xFF;
        bytes[0] = *(payload + i)>>24 & 0xFF;
	printf("pointer = %p: %d.%d.%d.%d\n",(void *) (payload+i), bytes[3],bytes[2],bytes[1],bytes[0]);
	i = i+1;
  }*/
  int protocol = proto;
  int src_ip = srcIp;
  int dst_ip = dstIp;
  int src_port = srcprt;
  int dst_port = dstprt;

  //Ask firewall for advice through ipc message
  if (fwdec_check_packet(protocol, src_ip, dst_ip, src_port, dst_port) != LWIP_KEEP_PACKET){
      //Drop packet
      printf("Dropping packet\n");
      pbuf_free(p);
    }
  printf("Keeping packet\n");
}
