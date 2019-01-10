#include <minix/ds.h>
#include <minix/fwdec.h>
#include <string.h>

#include "syslib.h"
#include <stdio.h>

/*
	* Sending IPC message to fwdec server
	* Returns a message with type LWIP_KEEP_PACKET or LWIP_DROP_PACKET
	*/
static int do_invoke_fwdec(message *m)
{
	int res = ipc_sendrec(FWDEC_PROC_NR,m);
	if (res != OK) {
	  return LWIP_DROP_PACKET;//If ipc fails we drop the packet for security reasons
	}

	switch (m->m_type) {
	  case LWIP_KEEP_PACKET:
	    return LWIP_KEEP_PACKET;
		case LWIP_DROP_PACKET:
		  return LWIP_DROP_PACKET;
		default:
			printf("lwip: warning, got illegal request from %d\n", m->m_source);
			return EINVAL;
	}
}

/*
 * Check packet function
 * Takes a pbuf and extracts source ip, destination ip, ports and protocol
 * Sends an IPC to the firewall
 */
int fwdec_check_packet(int protocol, int src_ip, int dst_ip, int src_port, int dst_port, int tcp_syn, int tcp_ack)
{
	message m;
	memset(&m, 0, sizeof(m));

	/* Prepare the request message for the firewall */
	m.m_type = FWDEC_CHECK_PACKET;
	m.m_fw_filter.protocol = protocol;
	m.m_fw_filter.src_ip = src_ip;
	m.m_fw_filter.dst_ip = dst_ip;
	m.m_fw_filter.src_port = src_port;
	m.m_fw_filter.dst_port = dst_port;
  m.m_fw_filter.tcp_syn = tcp_syn;
  m.m_fw_filter.tcp_ack= tcp_ack;

	return do_invoke_fwdec(&m);
}
