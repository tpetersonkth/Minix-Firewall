#include "inc.h"
#include "fwdec.h"
#include <minix/com.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

/* Declare local functions. */
static uint32_t stringToIp(char *string);
static void ipToString(uint32_t ip, char *outBuf, int bufLen);

/*===========================================================================*
 *		            sef_cb_init_fresh                                *
 *===========================================================================*/
int sef_cb_init_fresh(int UNUSED(type), sef_init_info_t *info)
{
  printf("Firewall decision server started\n");
  return(OK);
}

/*===========================================================================*
 *				do_publish				     *
 *===========================================================================*/
int check_packet(message *m_ptr)
{
  u8_t protocol = m_ptr->m_fw_filter.protocol;
  u32_t src_ip = m_ptr->m_fw_filter.src_ip;
  u32_t dst_ip = m_ptr->m_fw_filter.dst_ip;
  u16_t src_port = m_ptr->m_fw_filter.src_port;
  u16_t dst_port = m_ptr->m_fw_filter.dst_port;
  //printf("Invoked check packet with id: %d\n", m_ptr->m_type);
  //printf("Protocol: %d\nIP Source: %d\nIP Destination %d\nSource Port %d\nDestination Port %d\n", protocol, src_ip, dst_ip, src_port, dst_port);

  char srcIp[16];
  ipToString(src_ip,srcIp,16);

  char dstIp[16];
  ipToString(dst_ip,dstIp,16);

  printf("%d %s %s %d %d\n", protocol, srcIp, dstIp, src_port, dst_port);
  return(OK);
}


/*===========================================================================*
 *				ip format conversion					     *
 *===========================================================================*/
static void ipToString(uint32_t ip, char *outBuf, int bufLen){
  //Converts an IP in uint32 format to a printable format
  //Note, the caller has to ensure that buflen is >= 16

  char strIp[4][4] = {'\0','\0','\0','\0'};

  for(int i = 0; i <= 3; i++){
    uint32_t tmp = (ip&(0x000000FF<<(3-i)*8))>>8*(3-i);
    snprintf(strIp[i], 4,"%d", tmp);
  }
  snprintf(outBuf, bufLen,"%s.%s.%s.%s",strIp[0],strIp[1],strIp[2],strIp[3]);
}

static uint32_t stringToIp(char *string){
  //Converts an IP in string format, f.e "127.0.0.1" to a uint32
  uint32_t ip = 0;
  char strIp[4][4] = {'\0','\0','\0','\0'};
  int i1 = 0;
  int i2 = 0;

  while(*string!='\0'){
    if (*string=='.'){
      strIp[i1][i2] = '\0';
      i1++;
      i2=0;
      if (i1 > 3){//The supplied ip was to long
        break;
      }
    }
    else{
      strIp[i1][i2] = *string;
      i2++;
      if(i2>3){//Ip is of wrong format
        break;
      }
    }
    string++;
  }
  strIp[i1][i2] = '\0';

  for(int i = 0; i<= 3; i++){
    uint32_t tmp = atoi(strIp[i]);
    ip |= (tmp << (3-i)*8);
  }

  return ip;
}