SUBDIR+=pfresolvectl

PROG=		pfresolved
SRCS=		pfresolved.c
SRCS+=		forwarder.c log.c pftable.c proc.c timer.c util.c control.c
SRCS+=		parse.y
MAN=		pfresolved.8 pfresolved.conf.5
BINDIR?=	/usr/local/sbin
MANDIR?=	/usr/local/man/man

LDADD+=		-lutil -levent -lexecinfo -lunbound
DPADD+=		${LIBUTIL} ${LIBEVENT} ${LIBEXECINFO} ${LIBUNBOUND}

CFLAGS+=	-I${.CURDIR} -I/usr/local/include
CFLAGS+=	-Wall
CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=	-Wsign-compare

LDFLAGS+=	-L/usr/local/lib

VERSION=	1.03
CLEANFILES=	pfresolved-${VERSION}.tar.gz*
REGRESSFILES!=	make -C ${.CURDIR}/regress -V PERLS -V ARGS
CTLFILES!=	make -C ${.CURDIR}/pfresolvectl -V CTLFILES

.PHONY: dist pfresolved-${VERSION}.tar.gz
dist: pfresolved-${VERSION}.tar.gz
	gpg --armor --detach-sign pfresolved-${VERSION}.tar.gz
	@echo ${.OBJDIR}/pfresolved-${VERSION}.tar.gz

pfresolved-${VERSION}.tar.gz:
	rm -rf pfresolved-${VERSION}
	mkdir pfresolved-${VERSION}
.for f in README LICENSE Changes Makefile ${SRCS} pfresolved.h ${MAN}
	cp ${.CURDIR}/$f pfresolved-${VERSION}/
.endfor
	mkdir pfresolved-${VERSION}/regress
.for f in Makefile ${REGRESSFILES}
	cp ${.CURDIR}/regress/$f pfresolved-${VERSION}/regress/
.endfor
	mkdir pfresolved-${VERSION}/pfresolvectl
.for f in ${CTLFILES}
	cp ${.CURDIR}/pfresolvectl/$f pfresolved-${VERSION}/pfresolvectl/
.endfor
	tar -czvf $@ pfresolved-${VERSION}
	rm -rf pfresolved-${VERSION}

.PHONY: test
test: pfresolved
	PFRESOLVED=${.OBJDIR}/pfresolved ${MAKE} -C ${.CURDIR}/regress

.if (make(clean) || make(cleandir) || make(obj))
SUBDIR +=	regress
.endif

.include <bsd.prog.mk>
