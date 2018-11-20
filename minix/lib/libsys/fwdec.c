#include <minix/ds.h>
#include <minix/fwdec.h>
#include <string.h>

#include "syslib.h"

static int do_invoke_fwdec(message *m, int type)
{
	int r;

	r = _taskcall(FWDEC_PROC_NR, type, m);

	return r;
}

int fwdec_check_packet(void)
{
	message m;

	memset(&m, 0, sizeof(m));
	return do_invoke_fwdec(&m, FWDEC_CHECK_PACKET);
}
