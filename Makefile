PROG=		pfresolved
NOMAN=		yes
SRCS=		pfresolved.c
SRCS+=		forwarder.c log.c pftable.c proc.c timer.c util.c
SRCS+=		parse.y

LDADD+=		-lutil -levent -lexecinfo -lunbound
DPADD+=		${LIBUTIL} ${LIBEVENT} ${LIBEXECINFO} ${LIBUNBOUND}

CFLAGS+=	-I${.CURDIR} -I/usr/local/include
CFLAGS+=	-Wall
CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=	-Wsign-compare
CFLAGS+=	-Werror

LDFLAGS+=	-L/usr/local/lib

.include <bsd.prog.mk>
