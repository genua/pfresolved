PROG=		pfresolvectl
SRCS=		pfresolvectl.c parser.c
MAN=		pfresolvectl.8
BINDIR?=	/usr/local/sbin
MANDIR?=	/usr/local/man/man

LDADD+=		-lutil
DPADD+=		${LIBUTIL}

CFLAGS+=	-I${.CURDIR} -I${.CURDIR}/../ -I/usr/local/include
CFLAGS+=	-Wall
CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=	-Wsign-compare

LDFLAGS+=	-L/usr/local/lib

CTLFILES:=	${SRCS} ${MAN} parser.h Makefile

.include <bsd.prog.mk>
