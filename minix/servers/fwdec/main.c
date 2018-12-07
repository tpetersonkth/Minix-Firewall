#include "inc.h"	/* include master header file */
#include <minix/endpoint.h>
#include <stdlib.h>

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

//needed?
//#include "ntlm.h"

/* Allocate space for the global variables. */
static endpoint_t who_e;	/* caller's proc number */
static int callnr;		/* system call number */

/* Declare some local functions. */
static void get_work(message *m_ptr);
static void reply(endpoint_t whom, message *m_ptr);
static uint32_t stringToIp(char *string);
static void ipToString(uint32_t ip, char *outBuf);

/* SEF functions and variables. */
static void sef_local_startup(void);

/*===========================================================================*
 *				main                                         *
 *===========================================================================*/
int main(int argc, char **argv)
{
/* This is the main routine of this service. The main loop consists of 
 * three major activities: getting new work, processing the work, and
 * sending the reply. The loop never terminates, unless a panic occurs.
 */
  printf("fwdec starting\n");
  
  message m;
  int result;                 

  /* SEF local startup. */
  env_setargs(argc, argv);
  sef_local_startup();

  /* Main loop - get work and do it, forever. */         
  while (TRUE) {              

      /* Wait for incoming message, sets 'callnr' and 'who'. */
      get_work(&m);

      if (is_notify(callnr)) {
          printf("fwdec: warning, got illegal notify from: %d\n", m.m_source);
          result = EINVAL;
          goto send_reply;
      }
      switch (callnr) {
      case FWDEC_CHECK_PACKET:
          result = check_packet(&m);
          break;
      default: 
          printf("fwdec: warning, got illegal request from %d\n", m.m_source);
          result = EINVAL;
      }
      char p[16];
      ipToString(stringToIp("120.121.122.123"),p);
      //printf("Final IP: %s\n",p);

send_reply:
      /* Finally send reply message, unless disabled. */
      if (result != EDONTREPLY) {
          m.m_type = LWIP_DROP_PACKET;  		/* build reply message */
          reply(who_e, &m);		/* send it away */
      }
  }
  return(OK);				/* shouldn't come here */
}

/*===========================================================================*
 *			       sef_local_startup			     *
 *===========================================================================*/
static void sef_local_startup()
{
  /* Register init callbacks. */
  sef_setcb_init_fresh(sef_cb_init_fresh);
  sef_setcb_init_restart(sef_cb_init_fresh);

  /* Let SEF perform startup. */
  sef_startup();
}

/*===========================================================================*
 *				get_work                                     *
 *===========================================================================*/
static void get_work(
  message *m_ptr			/* message buffer */
)
{
    int status = sef_receive(ANY, m_ptr);   /* blocks until message arrives */
    if (OK != status)
        panic("failed to receive message!: %d", status);
    who_e = m_ptr->m_source;        /* message arrived! set sender */
    callnr = m_ptr->m_type;       /* set function call number */
}

/*===========================================================================*
 *				reply					     *
 *===========================================================================*/
static void reply(
  endpoint_t who_e,			/* destination */
  message *m_ptr			/* message buffer */
)
{
    int s = ipc_send(who_e, m_ptr);    /* send the message */
    if (OK != s)
        printf("fwdec: unable to send reply to %d: %d\n", who_e, s);
}

/*===========================================================================*
 *				ip format conversion					     *
 *===========================================================================*/
static void ipToString(uint32_t ip, char *outBuf){
    //Note, the caller has to ensure that the size of ipStr is >= 15

    char strIp[4][4] = {'\0','\0','\0','\0'};

    for(int i = 0; i <= 3; i++){
        uint32_t tmp = (ip&(0x000000FF<<(3-i)*8))>>8*(3-i);
        snprintf(strIp[i], sizeof(strIp[i]),"%d", tmp);
    }

    snprintf(outBuf, sizeof(outBuf),"%s.%s.%s.%s",strIp[0],strIp[1],strIp[2],strIp[3]);


}

static uint32_t stringToIp(char *string){//TODO Documentation

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