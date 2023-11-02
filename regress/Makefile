#	$OpenBSD$

.if exists(${.CURDIR}/../${.OBJDIR:T}/pfresolved)
PFRESOLVED ?=		${.CURDIR}/../${.OBJDIR:T}/pfresolved
.elif exists(${.CURDIR}/../pfresolved)
PFRESOLVED ?=		${.CURDIR}/../pfresolved
.endif

PERLS =			Proc.pm Pfresolved.pm funcs.pl pfresolved.pl
ARGS !=			cd ${.CURDIR} && ls args-*.pl
REGRESS_TARGETS =       ${ARGS:S/^/run-/}
CLEANFILES =		*.log *.conf ktrace.out stamp-* *.pid *.ktrace

# Set variables so that make runs with and without obj directory.
# Only do that if necessary to keep visible output short.

.if ${.CURDIR} == ${.OBJDIR}
PERLINC =	-I.
PERLPATH =
.else
PERLINC =	-I${.CURDIR} -I${.OBJDIR}
PERLPATH =	${.CURDIR}/
.endif

# The arg tests take a perl hash with arguments controlling the
# test parameters.  Generally they consist of client, syslogd, server.

.for a in ${ARGS}
run-$a: $a
	time SUDO=${SUDO} KTRACE=${KTRACE} PFRESOLVED=${PFRESOLVED} \
	    perl ${PERLINC} ${PERLPATH}pfresolved.pl ${PERLPATH}$a
.endfor

# make perl syntax check for all args files

.PHONY: syntax

syntax: stamp-syntax

stamp-syntax: ${PERLS} ${ARGS}
.for p in ${PERLS}
	@perl -c ${PERLINC} ${PERLPATH}$p
.endfor
.for a in ${ARGS}
	@perl -c ${PERLPATH}$a
.endfor
	@date >$@

.include <bsd.regress.mk>
