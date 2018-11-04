# Makefile for the group-names driver.
PROG=   group-names
SRCS=   group-names.c

FILES=${PROG}.conf
FILESNAME=${PROG}
FILESDIR= /etc/system.conf.d

CPPFLAGS+= -I${NETBSDSRCDIR}/minix

DPADD+= ${LIBCHARDRIVER} ${LIBSYS}
LDADD+= -lchardriver -lsys	# we use both the libsys (to implement a service) and the chardriver protocol

MAN=

.include <minix.service.mk>	# this is a service. Not a common process
