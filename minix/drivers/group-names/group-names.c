#include <stdio.h>
#include <stdlib.h>
#include <minix/syslib.h>
#include <minix/chardriver.h>
#include "group-names.h"

#include <minix/timers.h>
#include <include/arch/i386/include/archtypes.h>
#include "kernel/proc.h"
#include <minix/sysinfo.h>
#include <minix/myserver.h>
//#include <minix/fwdec.h>
#include "servers/pm/mproc.h"

/* SEF functions and variables. */
static void sef_local_startup(void);
static int sef_cb_init(int type, sef_init_info_t *info);
static int sef_cb_lu_state_save(int, int);
static int lu_state_restore(void);

/* State variable to count the number of times the device has been opened. */
static int open_counter;
const int BUF_LEN = 20;
char received_number[BUF_LEN] = NONUMBERMESSAGE;
char names[4][20] = {MEMBER1,MEMBER2,MEMBER3,MEMBER4};
int stored_num = -1;//-1 => Nothing stored

static int sef_cb_lu_state_save(int UNUSED(state), int UNUSED(flags)) {
  return OK;
}
 
static int lu_state_restore() {
  return OK;
}
  
static int sef_cb_init(int type, sef_init_info_t *UNUSED(info))
{
  /* Initialize the group-names driver. */
  int do_announce_driver = TRUE;
 
  open_counter = 0;
  switch(type) {
  case SEF_INIT_FRESH:
    printf("Initializing");
    break;
 
  case SEF_INIT_LU:
    /* Restore the state. */
    lu_state_restore();
    do_announce_driver = FALSE;
 
    printf("Hey, I'm a new version!\n");
    break;
 
  case SEF_INIT_RESTART:
    printf("Hey, I've just been restarted!\n");
    break;
  }

  /* Announce we are up when necessary. */
  if (do_announce_driver) {
    chardriver_announce();
  }
 
  /* Initialization completed successfully. */
  return OK;
}

static void sef_local_startup()
{
  /*
   * Register init callbacks. Use the same function for all event types
   */
  sef_setcb_init_fresh(sef_cb_init);
  sef_setcb_init_lu(sef_cb_init);
  sef_setcb_init_restart(sef_cb_init);
 
  /*
   * Register live update callbacks.
   */
  sef_setcb_lu_state_save(sef_cb_lu_state_save);
 
  /* Let SEF perform startup. */
  sef_startup();
}


/*
 * Function prototypes for the group-names driver.
 */
static int groupNames_open(devminor_t minor, int access, endpoint_t user_endpt);
static int groupNames_close(devminor_t minor);
static ssize_t groupNames_read(devminor_t minor, u64_t position, endpoint_t endpt,
    cp_grant_id_t grant, size_t size, int flags, cdev_id_t id);
static ssize_t groupNames_write(devminor_t minor, u64_t position, endpoint_t endpt,
			   cp_grant_id_t grant, size_t size, int flags, cdev_id_t id);

/* Entry points to the group-names driver. */
static struct chardriver groupNames_tab =
{
 .cdr_open	= groupNames_open,
 .cdr_close	= groupNames_close,
 .cdr_read	= groupNames_read,
 .cdr_write = groupNames_write,
};

static int groupNames_open(devminor_t UNUSED(minor), int UNUSED(access),
                      endpoint_t UNUSED(user_endpt))
{
  //printf("groupNames_open(). Called %d time(s).\n", ++open_counter);

  //fwdec_check_packet();
  myserver_sys1();
  return OK;
}
 
static int groupNames_close(devminor_t UNUSED(minor))
{
  //printf("groupNames_close()\n");
  return OK;
}
 
static ssize_t groupNames_read(devminor_t UNUSED(minor), u64_t position,
                          endpoint_t endpt, cp_grant_id_t grant, size_t size, int UNUSED(flags),
                          cdev_id_t UNUSED(id))
{
  u64_t dev_size;
  char *ptr;
  int ret;

  char *buf = received_number;
  if (1 <= stored_num && stored_num <= 4){
    buf = names[stored_num-1];
  }

  //printf("groupNames_read()\n");
 
  /* This is the total size of our device. */
  dev_size = (u64_t) strlen(buf);
 
  /* Check for EOF, and possibly limit the read size. */
  if (position >= dev_size) return 0;		/* EOF */
  if (position + size > dev_size)
    size = (size_t)(dev_size - position);	/* limit size */
 
  /* Copy the requested part to the caller. */
  ptr = buf + (size_t)position;
  if ((ret = sys_safecopyto(endpt, grant, 0, (vir_bytes) ptr, size)) != OK)
    return ret;
 
  /* Return the number of bytes read. */
  return size;
}

static ssize_t groupNames_write(devminor_t UNUSED(minor), u64_t position,
			  endpoint_t endpt, cp_grant_id_t grant, size_t size, int UNUSED(flags),
			  cdev_id_t UNUSED(id))
{
  int r;
  //printf("groupNames_write(position=%llu, size=%zu)\n", position, size);

  if (size > BUF_LEN)//Avoid writing outside of buffer..
    size = (size_t)(BUF_LEN);

  r = sys_safecopyfrom(endpt, grant, 0, (vir_bytes) (received_number), size);
  if (r != OK) {
    printf("GROUPNAMES: warning: couldn't copy data %d\n", r);
    return OK;
  }
  received_number[size] = '\0';
  //printf("received=%s\n", received_number);

  stored_num = atoi(received_number);
  //printf("Stored number:%d\n", stored_num);

  return size;
}


int main(void)
{
  //Perform initialization.
  sef_local_startup();

  //Run the main loop.
  chardriver_task(&groupNames_tab);
  return OK;
}
