#include "inc.h"
#include "fwdec.h"
#include <minix/com.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>

/* Declare local functions. */
static uint32_t stringToIp(char *string);
static void ipToString(uint32_t ip, char *outBuf, int bufLen);
void loadConfigurations(void);
bool filter(uint8_t proto, uint32_t srcIp, uint32_t  dstIp, uint16_t  srcPort,uint16_t  dstPort);

/* Global variables */
static int mode = MODE_NOTSET;
Rule* rules = 0;

/*===========================================================================*
 *		            sef_cb_init_fresh                                        *
 *===========================================================================*/
int sef_cb_init_fresh(int UNUSED(type), sef_init_info_t *info)
{
  printf("Firewall decision server started\n");
  return(OK);
}

/*===========================================================================*
 *				do_publish				                                     *
 *===========================================================================*/
int check_packet(message *m_ptr)
{
  u8_t protocol = m_ptr->m_fw_filter.protocol;
  u32_t src_ip = m_ptr->m_fw_filter.src_ip;
  u32_t dst_ip = m_ptr->m_fw_filter.dst_ip;
  u16_t src_port = m_ptr->m_fw_filter.src_port;
  u16_t dst_port = m_ptr->m_fw_filter.dst_port;

  bool res = filter(protocol, src_ip, dst_ip, src_port, dst_port);

  //Avoided nested ternary for clarity and readability! /Thomas
  if (mode == MODE_WHITELIST){
    return res ? LWIP_KEEP_PACKET : LWIP_DROP_PACKET;
  }
  else{
    return res ? LWIP_DROP_PACKET : LWIP_KEEP_PACKET;
  }
}


/*===========================================================================*
 *				ip format conversion					                     *
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

/*===========================================================================*
 *				configurations                                                     *
 *===========================================================================*/

void loadConfigurations(){
  mode = MODE_WHITELIST;//Hard coded for now
  printf("[FWDEC] Loading firewall rules");

  Rule* dnsRule = malloc(sizeof(Rule));
  *dnsRule = RuleDefault;//Set all fields to 0, meaning don't care
  dnsRule->dstIp = stringToIp("10.0.2.3");
  dnsRule->dstPort = 53;

  Rule* dnsAnsRule = malloc(sizeof(Rule));
  *dnsAnsRule = RuleDefault;//Set all fields to 0, meaning don't care
  dnsAnsRule->srcIp = stringToIp("10.0.2.3");
  dnsAnsRule->srcPort = 53;

  dnsRule->next = dnsAnsRule;

  rules = dnsRule;
}

/*===========================================================================*
 *				filtering                                                          *
 *===========================================================================*/
bool filter(uint8_t proto, uint32_t srcIp, uint32_t  dstIp, uint16_t  srcPort, uint16_t  dstPort){
  //Returns true if the packet matches a rule, otherwise false

  if(mode == MODE_NOTSET){//If configurations hasn't been loaded yet
      loadConfigurations();
  }

  char srcIpS[16];
  ipToString(srcIp,srcIpS,16);
  char dstIpS[16];
  ipToString(dstIp,dstIpS,16);

  printf("%d %s %s %d %d\n", proto, srcIpS, dstIpS, srcPort, dstPort);

  Rule* currRule = rules;
  int ruleCount = 1;
  while(currRule != 0){
    ipToString(currRule->srcIp,srcIpS,16);
    ipToString(currRule->dstIp,dstIpS,16);
    printf("Rule %d: %d %s %s %d %d\n", ruleCount,currRule->proto, srcIpS, dstIpS, currRule->srcPort, currRule->dstPort);
    //Check protocol
    if (currRule->proto == 0 || proto == currRule->proto) {
      //Check ips, masks have not been added yet
      if ((currRule->srcIp == 0 || srcIp == currRule->srcIp) && (currRule->dstIp == 0 || dstIp == currRule->dstIp)) {
        //Check ports
        if ((currRule->srcPort == 0 || currRule->srcPort == srcPort)&&(currRule->dstPort == 0 || currRule->dstPort == dstPort)){
          printf("Packet matched rule %d!\n",ruleCount);
          return true;
        }
      }
    }
    currRule = currRule->next;
    ruleCount++;
  }
  return false;
}

