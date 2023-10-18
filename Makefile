PROG=		pfresolved
NOMAN=		yes
SRCS=		pfresolved.c
SRCS+=		forwarder.c log.c pftable.c proc.c timer.c util.c
SRCS+=		parse.y

LDADD+=		-lutil -levent -lexecinfo
DPADD+=		${LIBUTIL} ${LIBEVENT} ${LIBEXECINFO}

CFLAGS+=	-DGENUOS
CFLAGS+=	-I${.CURDIR}/../../ports/w-net@libunbound/unbound-1.17.1/libunbound
CFLAGS+=	-Wall -I${.CURDIR}
CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=	-Wsign-compare
CFLAGS+=	-Werror

MAKEOBJDIR?=obj.${MACHINE}
LDADD+= -L${.CURDIR}/../libunbound/${MAKEOBJDIR} -lunbound
DPADD+= ${.CURDIR}/../libunbound/${MAKEOBJDIR}/libunbound.a

.include <bsd.prog.mk>
