#include <minix/ds.h>
#include <minix/fwdec.h>
#include <string.h>

#include "syslib.h"
#include <stdio.h>

static int do_invoke_fwdec(message *m, int type)
{
	int r;

	r = _taskcall(FWDEC_PROC_NR, type, m);

	return r;
}

int fwdec_check_packet(void)
{
	printf("libsys/fwdec_check_packet\n");
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
