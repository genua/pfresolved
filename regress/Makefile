#	$OpenBSD$

.if exists(${.CURDIR}/../${.OBJDIR:T}/pfresolved)
PFRESOLVED ?=		${.CURDIR}/../${.OBJDIR:T}/pfresolved
.elif exists(${.CURDIR}/../pfresolved)
PFRESOLVED ?=		${.CURDIR}/../pfresolved
.endif

PERLS =			Nsd.pm Pfctl.pm Pfresolved.pm Proc.pm \
			funcs.pl pfresolved.pl
ARGS !=			cd ${.CURDIR} && ls args-*.pl
REGRESS_TARGETS =       ${ARGS:S/^/run-/}
CLEANFILES =		*.log *.conf ktrace.out stamp-* *.pid *.ktrace *.zone

REGRESS_SETUP_ONCE =	chmod-obj
chmod-obj:
	# nsd user needs read permission for zone file
	-chmod o+rx ${.OBJDIR}

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

# create certificates for TLS

CLEANFILES +=	*.crt *.key *.req *.srl

ca.crt badca.crt:
	openssl req -batch -new \
	    -subj /L=OpenBSD/O=pfresolved-regress/OU=ca/CN=root/ \
	    -nodes -newkey rsa -keyout ${@:R}.key -x509 -out $@

server.req:
	openssl req -batch -new \
	    -subj /L=OpenBSD/O=pfresolved-regress/OU=${@:R}/CN=localhost/ \
	    -nodes -newkey rsa -keyout ${@:R}.key -out $@

server.crt: ca.crt ${@:R}.req
	openssl x509 -CAcreateserial -CAkey ca.key -CA ca.crt -req \
	    -in ${@:R}.req -out $@

${REGRESS_TARGETS:M*tls*}: server.crt
${REGRESS_TARGETS:M*tls-bad*}: badca.crt

# create zone and key signing keys for DNSSEC

CLEANFILES +=	*.key *.private *.ds .key .private .ds

zsk.key:
	rm -f ${@:R}.*
	ldns-keygen -a ED25519 -sf regress
	mv .key ${@:R}.key
	mv .private ${@:R}.private

ksk.key badksk.key:
	rm -f ${@:R}.*
	ldns-keygen -a ED25519 -k -sf regress
	mv .key ${@:R}.key
	mv .private ${@:R}.private
	mv .ds ${@:R}.ds

${REGRESS_TARGETS:M*dnssec*}: zsk.key ksk.key
${REGRESS_TARGETS:M*dnssec-bad*}: badksk.key

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
