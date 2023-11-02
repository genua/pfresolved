PROG=		pfresolved
SRCS=		pfresolved.c
SRCS+=		forwarder.c log.c pftable.c proc.c timer.c util.c
SRCS+=		parse.y
MAN=		pfresolved.8 pfresolved.conf.5

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

test: pfresolved
	PFRESOLVED=${.OBJDIR}/pfresolved ${MAKE} -C ${.CURDIR}/regress

.if (make(clean) || make(cleandir) || make(obj))
SUBDIR +=	regress
.endif

.include <bsd.prog.mk>
