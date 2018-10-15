#include <minix/ds.h>
#include <minix/myserver.h>
#include <string.h>

#include "syslib.h"

static int do_invoke_myserver(message *m, int type)
{
	int r;

	r = _taskcall(MYSERVER_PROC_NR, type, m);

	return r;
}

int myserver_sys1(void)
{
	message m;

	memset(&m, 0, sizeof(m));
	return do_invoke_myserver(&m, MYSERVER_SYS1);
}
