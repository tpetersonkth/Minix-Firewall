#include <minix/ds.h>
#include <minix/fwdec.h>
#include <string.h>

#include "syslib.h"
#include <stdio.h>

static int do_invoke_fwdec(message *m, int type)//TODO remove type parameter
{
	int r;

	/*
	 * Sending IPC message to fwdec server
	 * Returns a message with type LWIP_KEEP_PACKET or LWIP_DROP_PACKET
	 */
   	ipc_sendrec(FWDEC_PROC_NR,m);//TODO: handle errors

   	switch (m->m_type) {
		case LWIP_KEEP_PACKET:
		    r = LWIP_KEEP_PACKET;
			break;
		case LWIP_DROP_PACKET:
		    r = LWIP_DROP_PACKET;
			break;
		default:
			printf("lwip: warning, got illegal request from %d\n", m->m_source);
			r = EINVAL;
	}

	return r;
}

int fwdec_check_packet(void)
{
	message m;
	memset(&m, 0, sizeof(m));

	/* Prepare the request message for the firewall */
	m.m_type = FWDEC_CHECK_PACKET;
	m.m_fw_filter.protocol = 1;
	m.m_fw_filter.src_ip = 2;
	m.m_fw_filter.dst_ip = 3;
	m.m_fw_filter.src_port = 4;
	m.m_fw_filter.dst_port = 5;

	return do_invoke_fwdec(&m, FWDEC_CHECK_PACKET);
}
