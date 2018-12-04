#include "inc.h"
#include "fwdec.h"
#include <minix/com.h>


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
  int message1 = m_ptr->m_fw_test.test1;
  int message2 = m_ptr->m_fw_test.test2;
  printf("Invoked check packet with id: %d\n", m_ptr->m_type);
  printf("Results: %d and %d\n", message1, message2);
  return(OK);
}

