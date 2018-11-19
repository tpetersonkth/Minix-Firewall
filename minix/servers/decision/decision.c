#include "inc.h"
#include "decision.h"


/*===========================================================================*
 *		            sef_cb_init_fresh                                *
 *===========================================================================*/
int sef_cb_init_fresh(int UNUSED(type), sef_init_info_t *info)
{
  printf("Decision server started\n");
  return(OK);
}

/*===========================================================================*
 *				do_publish				     *
 *===========================================================================*/
int do_sys1(message *m_ptr)//This function can not be used yet since I haven't set up messages for this server yet /Thomas
{
  printf("invoked the syscall 01\n");
  return(OK);
}

