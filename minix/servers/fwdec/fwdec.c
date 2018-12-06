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
  u8_t protocol = m_ptr->m_fw_filter.protocol;
  u32_t src_ip = m_ptr->m_fw_filter.src_ip;
  u32_t dst_ip = m_ptr->m_fw_filter.dst_ip;
  u16_t src_port = m_ptr->m_fw_filter.src_port;
  u16_t dst_port = m_ptr->m_fw_filter.dst_port;
  //printf("Invoked check packet with id: %d\n", m_ptr->m_type);
  //printf("Protocol: %d\nIP Source: %d\nIP Destination %d\nSource Port %d\nDestination Port %d\n", protocol, src_ip, dst_ip, src_port, dst_port);
  return(OK);
}

