/*
 * fwdec - Firewall decision server
 * Author: Thomas Peterson
 */

#include "inc.h"
#include "fwdec.h"
#include <minix/com.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h> //File handling
#include <fcntl.h> //File handling flags
#include <sys/time.h> //System time


/* Declare local functions. */
static uint32_t stringToIp(char *string);
static void ipToString(uint32_t ip, char *outBuf, int bufLen);
void loadConfigurations(void);
int filter(uint8_t proto, uint32_t srcIp, uint32_t  dstIp, uint16_t  srcPort,uint16_t  dstPort);
int tcpSynProtection(uint8_t proto, uint32_t srcIp, uint8_t syn, uint8_t ack);
void logConfigurations(void);
void logToLogfile(char* logfile,char* logEntry, int length);
int packetToString(char* buf, int buflen, uint8_t proto, uint32_t srcIp, uint32_t  dstIp, uint16_t  srcPort, uint16_t  dstPort);
char *itoa(int n);

/* Global variables */
static int mode = MODE_NOTSET;
Rule* rules = 0;
tcpSynProt* tcpSynConnections = 0;

static int next;
static char qbuf[8];

/* Global variables - Configurables */
const char *LOGFILE = "/var/log/fwdec"; //Where the log file should be placed
const int defaultMode = MODE_WHITELIST; //Might be exported to config file in the future
int TCP_PROTECTION_TIMEOUT = 30; //The amount of seconds before a tcp protection entry is reset
int TCP_MAX_SYNCOUNT = 5; //The maximum amount of suspicious SYN packets allowed from a host

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
  u8_t proto = m_ptr->m_fw_filter.protocol;
  u32_t srcIp = m_ptr->m_fw_filter.src_ip;
  u32_t dstIp = m_ptr->m_fw_filter.dst_ip;
  u16_t srcPort = m_ptr->m_fw_filter.src_port;
  u16_t dstPort = m_ptr->m_fw_filter.dst_port;
  u8_t tcpSyn = m_ptr->m_fw_filter.tcp_syn;
  u8_t tcpAck = m_ptr->m_fw_filter.tcp_ack;

#if (FWDEC_DEBUG == 1)
  if (proto == IP_PROTO_TCP){
    printf("Recieved SYN: %d and ACK: %d\n",tcpSyn,tcpAck);
  }
#endif

  if (tcpSynProtection(proto, srcIp, tcpSyn, tcpAck) != LWIP_KEEP_PACKET){

    //Log to logfile
    logToLogfile((char *) LOGFILE, "[Packet Dropped|Suspicious TCP behaviour] ",42);

    char logEntry[82];
    int entryLen = packetToString(logEntry, 82, proto, srcIp, dstIp, srcPort, dstPort);
    logToLogfile((char *)LOGFILE,logEntry,entryLen);

    logToLogfile((char *)LOGFILE,"\n",1);

    return LWIP_DROP_PACKET;
  }

  int res = filter(proto, srcIp, dstIp, srcPort, dstPort);

  if (mode == MODE_WHITELIST && res == 0){
      logToLogfile((char *) LOGFILE, "[Packet Dropped|Not in whitelist] ",33);

      char logEntry[82];
      int entryLen = packetToString(logEntry, 82, proto, srcIp, dstIp, srcPort, dstPort);
      logToLogfile((char *)LOGFILE,logEntry,entryLen);

      logToLogfile((char *)LOGFILE,"\n",1);

      return LWIP_DROP_PACKET;

  }
  else if (mode == MODE_BLACKLIST && res != 0){
    //Log the drop
    logToLogfile((char *)LOGFILE,"[Packet dropped|Violated rule ",30);

    char *vioRule = itoa(res);
    logToLogfile((char *)LOGFILE,vioRule,strlen(vioRule));
    logToLogfile((char *)LOGFILE,"] ",2);

    char logEntry[82];
    int entryLen = packetToString(logEntry, 82, proto, srcIp, dstIp, srcPort, dstPort);
    logToLogfile((char *)LOGFILE,logEntry,entryLen);

    logToLogfile((char *)LOGFILE,"\n",1);
    return LWIP_DROP_PACKET;

  }

  return LWIP_KEEP_PACKET;
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
  mode = defaultMode;

  Rule* dnsRule = malloc(sizeof(Rule));
  *dnsRule = RuleDefault;//Set all fields to 0, meaning don't care
  dnsRule->dstIp = stringToIp("10.0.2.3");
  dnsRule->dstPort = 53;

  Rule* dnsAnsRule = malloc(sizeof(Rule));
  *dnsAnsRule = RuleDefault;//Set all fields to 0, meaning don't care
  dnsAnsRule->srcIp = stringToIp("10.0.2.3");
  dnsAnsRule->srcPort = 53;

  Rule* toKthRule = malloc(sizeof(Rule));
  *toKthRule = RuleDefault;//Set all fields to 0, meaning don't care
  toKthRule->dstIp = stringToIp("130.237.28.40");

  Rule* fromKthRule = malloc(sizeof(Rule));
  *fromKthRule = RuleDefault;//Set all fields to 0, meaning don't care
  fromKthRule->srcIp = stringToIp("130.237.28.40");

  Rule* allowUDP25 = malloc(sizeof(Rule));
  *allowUDP25 = RuleDefault;//Set all fields to 0, meaning don't care
  allowUDP25->proto = 17;
  allowUDP25->dstPort = 25;

  Rule* allowTCP23 = malloc(sizeof(Rule));
  *allowTCP23 = RuleDefault;//Set all fields to 0, meaning don't care
  allowTCP23->proto = 6;
  allowTCP23->dstPort = 23;

  Rule* sendToGateway = malloc(sizeof(Rule));
  *sendToGateway = RuleDefault;
  sendToGateway->dstIp = stringToIp("10.0.2.2");

  Rule* allowAll = malloc(sizeof(Rule));
  *allowAll = RuleDefault;//Set all fields to 0, meaning don't care

  /*******************************************
   * TEST CASE 1
   * only allow DNS messages that uses port 53
   *******************************************/
  rules = dnsRule;
  dnsRule->next = dnsAnsRule;
  /*****************
   * TEST CASE 1 END
   *****************/

  /************************************************
   * TEST CASE 2
   * only allow DNS and traffic to and from KTH.se
   ***********************************************/
  //rules = dnsRule;
  //dnsRule->next = dnsAnsRule;
  //dnsAnsRule->next = toKthRule;
  //toKthRule->next = fromKthRule;
  /*****************
   * TEST CASE 2 END
   *****************/

  /*****************************************
   * TEST CASE 3
   * allow TCP on port 23 and UDP on port 25
   *****************************************/
  //rules = allowUDP25;
  //allowUDP25->next = allowTCP23;
  //allowTCP23->next = sendToGateway;
  /*****************
   * TEST CASE 3 END
   *****************/

  logToLogfile((char *)LOGFILE,"Firewall configurations loaded successfully\n",44);
  logConfigurations();
}

/*===========================================================================*
 *				filtering                                                          *
 *===========================================================================*/
int filter(uint8_t proto, uint32_t srcIp, uint32_t  dstIp, uint16_t  srcPort, uint16_t  dstPort){
  //Filters based on the headers and a set of firewall rules
  //Returns the rule number if the packet matches a rule, otherwise 0

  if(mode == MODE_NOTSET){//If configurations hasn't been loaded yet
      loadConfigurations();
  }

  char srcIpS[16];
  char dstIpS[16];

  ipToString(srcIp,srcIpS,16);
  ipToString(dstIp,dstIpS,16);

#if (FWDEC_DEBUG == 1)
    printf("[FWDEC|Filter] Proto:%d srcIp:%s srcPort:%d dstIp:%s dstPort:%d\n", proto, srcIpS, srcPort, dstIpS, dstPort);
#endif

  Rule* currRule = rules;
  int ruleCount = 1;
  while(currRule != 0){
    ipToString(currRule->srcIp,srcIpS,16);
    ipToString(currRule->dstIp,dstIpS,16);
    //Check protocol
    if (currRule->proto == 0 || proto == currRule->proto) {
      //Check ips, masks have not been added yet
      if ((currRule->srcIp == 0 || srcIp == currRule->srcIp) && (currRule->dstIp == 0 || dstIp == currRule->dstIp)) {
        //Check ports
        if ((currRule->srcPort == 0 || currRule->srcPort == srcPort)&&(currRule->dstPort == 0 || currRule->dstPort == dstPort)){
          return ruleCount;
        }
      }
    }
    currRule = currRule->next;
    ruleCount++;
  }

  return 0;
}

int tcpSynProtection(uint8_t proto, uint32_t srcIp, uint8_t syn, uint8_t ack){
  //Keeps track of which ips have sent syn packets and if they have sent acks for these
  //Blacklists misbehaving clients

  time_t timestamp = time(NULL);

  if (proto != IP_PROTO_TCP){
#if (FWDEC_DEBUG == 1)
    printf("[FWDEC_TCP_PROT] Keeping, protocol is not TCP!\n");
#endif
    return LWIP_KEEP_PACKET;
  }

  if (syn > 1 || ack > 1){//syn and ack flag should always be 1 or 0
    //Should never arrive here unless someone has called the function with wrong values for syn or ack
    logToLogfile((char *)LOGFILE,"WARNING: Received malformed syn and ack values\n",47);
    printf("[FWDEC_TCP_PROT] Recieved malformed syn and ack values\n");
    return LWIP_DROP_PACKET;
  }

  //find the matching entry
  tcpSynProt* previous = 0;
  tcpSynProt* current = tcpSynConnections;
  while(current != 0){
    if (current->srcIp == srcIp){//Can easily be compared since both are stored as ints! :)
      break;
    }
    previous = current;
    current = current->next;
  }

  if (current == 0){//Source Ip was not found in list
#if (FWDEC_DEBUG == 1)
    printf("[FWDEC_TCP_PROT] Creating new item in tcp syn list!\n");
#endif
    tcpSynProt* newEntry = malloc(sizeof(tcpSynProt));
    newEntry->srcIp = srcIp;
    newEntry->synCount = 0;
    newEntry->timestamp = timestamp;

    //Add to list
    if (tcpSynConnections == 0){//list is empty
      tcpSynConnections = newEntry;
    }
    else if (previous == 0){//list has one element
      tcpSynConnections->next = newEntry;
    }
    else{
      previous->next = newEntry;
    }

    current = newEntry;
  }

  //Check for too many unjustified syns
  if (current->synCount >= TCP_MAX_SYNCOUNT){
#if (FWDEC_DEBUG == 1)
    printf("[FWDEC_TCP_PROT] Blocking blacklisted IP as syn count is too high!\n");
#endif
    return LWIP_DROP_PACKET;
  }

  //Reset count if too much time has passed
  if((timestamp - current->timestamp) > TCP_PROTECTION_TIMEOUT){
#if (FWDEC_DEBUG == 1)
    printf("[FWDEC_TCP_PROT] Resetting timestamp!\n");
#endif
    current->timestamp = timestamp;
    current->synCount = 0;
  }

  //Update synCount
  current->synCount = ((syn == 0 && ack == 1 && current->synCount == 0)?0:current->synCount+syn-ack); //syn and ack values can only be 1 or 0

#if (FWDEC_DEBUG == 1)
  printf("[FWDEC_TCP_PROT] Keeping tcp packet!\n");
#endif
  return LWIP_KEEP_PACKET;
}



/*===========================================================================*
 *				logging                                                          *
 *===========================================================================*/
void logConfigurations(){
  char *modeS = mode == MODE_BLACKLIST ? "Mode: Blacklist\n": "Mode: Whitelist\n";
  logToLogfile((char *)LOGFILE,modeS,strlen(modeS));

  Rule* currRule = rules;
  int ruleCount = 1;
  while(currRule != 0){
    char *string;//Use for temporary conversions
    char* ipString[16];//For holding ip in string format temporarily

    logToLogfile((char *)LOGFILE,"Rule ",5);

    string = itoa(ruleCount);
    logToLogfile((char *)LOGFILE,string,strlen((char *)string));

    logToLogfile((char *)LOGFILE," Proto:",7);

    string = itoa(currRule->proto);
    logToLogfile((char *)LOGFILE,string,strlen((char *)string));

    logToLogfile((char *)LOGFILE," srcIp:",7);

    ipToString(currRule->srcIp,(char *)ipString,16);
    logToLogfile((char *)LOGFILE,(char *)ipString,strlen((char *)ipString));

    logToLogfile((char *)LOGFILE," srcPort:",9);

    string = itoa(currRule->srcPort);
    logToLogfile((char *)LOGFILE,string,strlen((char *)string));

    logToLogfile((char *)LOGFILE," dstIp:",7);

    ipToString(currRule->dstIp,(char *)ipString,16);
    logToLogfile((char *)LOGFILE,(char *)ipString,strlen((char *)ipString));
    logToLogfile((char *)LOGFILE," dstPort:",9);

    string = itoa(currRule->dstPort);
    logToLogfile((char *)LOGFILE,string,strlen((char *)string));

    logToLogfile((char *)LOGFILE,"\n",1);

    currRule = currRule->next;
    ruleCount++;
  }

}

void logToLogfile(char* logFile,char* logEntry, int length){
  //Writes logentry to logfile using vfs syscall wrappers
  int fd = open(logFile, O_WRONLY|O_CREAT|O_APPEND);
  if (fd == -1){
    printf("Warning: fwdec failed to open log file %s\n",logFile);
  }

  int bytesWritten = write(fd, logEntry, length);
  if (bytesWritten != length){
    printf("Warning: fwdec failed to write to log file");
  }
  close(fd);
}

int packetToString(char* buf, int buflen, uint8_t proto, uint32_t srcIp, uint32_t  dstIp, uint16_t  srcPort, uint16_t  dstPort){

  const char* origBuf = buf;

  const int minBufsize = 82; // = [Size of params]+[size of formatting]=(3+15+15+5+5)+(6+7+9+7+9+1) = 43 + 39 = 82
  if (buflen >= minBufsize){ //Avoid buffer overflows, caller is responsible for providing a large enough buffer
    char* string; //for holding port conversion temporarily
    char* ipString[16]; //for holding ip in string format temporarily

    strncpy(buf,"Proto:",6);
    buf = buf + 6;

    string = itoa(proto);
    strncpy(buf,string,strlen(string));
    buf = buf + strlen(string);

    strncpy(buf," srcIp:",7);
    buf = buf + 7;

    ipToString(srcIp,(char *)ipString,16);
    strncpy(buf,(char *)ipString,strlen((char *)ipString));
    buf = buf + strlen((char *)ipString);

    strncpy(buf," srcPort:",9);
    buf = buf + 9;

    string = itoa(srcPort);
    strncpy(buf,string,strlen(string));
    buf = buf + strlen(string);

    strncpy(buf," dstIp:",7);
    buf = buf + 7;

    ipToString(dstIp,(char *)ipString,16);
    strncpy(buf,(char *)ipString,strlen((char *)ipString));
    buf = buf + strlen((char *)ipString);

    strncpy(buf," dstPort:",9);
    buf = buf + 9;

    string = itoa(dstPort);
    strncpy(buf,string,strlen(string));
    buf = buf + strlen(string);

    *buf = '\0';
  }

  return buf - origBuf; //returns the length of the string
}

/*===========================================================================*
 *				Utilities                                                          *
 *===========================================================================*/

//Copied from minix/lib/libc/gen/itoa.c as services can not access the full stdlib.
char *itoa(int n)
{
  register int r, k;
  int flag = 0;

  next = 0;
  if (n < 0) {
    qbuf[next++] = '-';
    n = -n;
  }
  if (n == 0) {
    qbuf[next++] = '0';
  } else {
    k = 10000;
    while (k > 0) {
      r = n / k;
      if (flag || r > 0) {
        qbuf[next++] = '0' + r;
        flag = 1;
      }
      n -= r * k;
      k = k / 10;
    }
  }
  qbuf[next] = 0;
  return(qbuf);
}
