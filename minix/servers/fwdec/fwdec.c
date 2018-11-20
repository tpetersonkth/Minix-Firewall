#include "inc.h"
#include "fwdec.h"


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
  printf("Invoked check packet\n");
  return(OK);
}

