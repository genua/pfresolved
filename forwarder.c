/*
 * Copyright (c) 2023 genua GmbH
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pfresolved.h"

#define DNS_CLASS_IN		1
#define DNS_RR_TYPE_A		1
#define DNS_RR_TYPE_AAAA	28
#define DNS_RCODE_NOERROR	0
#define DNS_RCODE_NXDOMAIN	3

void	 forwarder_run(struct privsep *, struct privsep_proc *, void *);
void	 forwarder_shutdown(void);
int	 forwarder_dispatch_parent(int, struct privsep_proc *, struct imsg *);
void	 forwarder_process_resolvereq(struct pfresolved *, struct imsg *);
void	 forwarder_ub_ctx_init(struct pfresolved *);
void	 forwarder_ub_resolve_async_cb(void *, int, struct ub_result *);
void	 forwarder_ub_resolve_async_cb_discard(void *, int, struct ub_result *);
void	 forwarder_ub_fd_read_cb(int, short, void *);

static struct privsep_proc procs[] = {
	{ "parent", PROC_PARENT, forwarder_dispatch_parent }
};

void
forwarderproc(struct privsep *ps, struct privsep_proc *p)
{
	struct pfresolved	*env = ps->ps_env;

	forwarder_ub_ctx_init(env);

	/*
	 * Libunbound only reads configured files (e.g. certificate bundles for
	 * DoT) when the first resolve is done. We need to do this before we
	 * call chroot(2). Therefore we simply query for "localhost" here and
	 * then discard the result.
	 */
	ub_resolve_async(env->sc_ub_ctx, "localhost", DNS_RR_TYPE_A,
	    DNS_CLASS_IN, NULL, forwarder_ub_resolve_async_cb_discard, NULL);

	proc_run(ps, p, procs, nitems(procs), forwarder_run, NULL);
}

void
forwarder_run(struct privsep *ps, struct privsep_proc *p, void *arg)
{
	struct pfresolved	*env = ps->ps_env;
	int			 fd;

	if (pledge("stdio inet rpath", NULL) == -1)
		fatal("%s: pledge", __func__);

	if ((fd = ub_fd(env->sc_ub_ctx)) == -1)
		fatalx("%s: ub_fd failed", __func__);

	event_set(&env->sc_ub_fd_event, fd, EV_READ | EV_PERSIST,
	    forwarder_ub_fd_read_cb, env);
	event_add(&env->sc_ub_fd_event, NULL);

	p->p_shutdown = forwarder_shutdown;
}

void forwarder_shutdown(void)
{
	struct pfresolved	*env = pfresolved_env;

	event_del(&env->sc_ub_fd_event);
	ub_ctx_delete(env->sc_ub_ctx);
}

int
forwarder_dispatch_parent(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	struct pfresolved	*env = pfresolved_env;

	switch (imsg->hdr.type) {
	case IMSG_RESOLVEREQ:
		forwarder_process_resolvereq(env, imsg);
		break;
	default:
		return (-1);
		break;
	}

	return (0);
}

void
forwarder_process_resolvereq(struct pfresolved *env, struct imsg *imsg)
{
	uint8_t				*ptr;
	size_t				 len;
	sa_family_t			 af;
	char				*hostname;
	int				 request_type, res, hostname_len;
	struct iovec			 iov[3];
	int				 iovcnt = 0;

	ptr = imsg->data;
	len = IMSG_DATA_SIZE(imsg);

	if (len < sizeof(af))
		fatalx("%s: imsg length too small", __func__);

	memcpy(&af, ptr, sizeof(af));
	ptr += sizeof(af);
	len -= sizeof(af);

	if ((hostname = calloc(len + 1, sizeof(char))) == NULL)
		fatal("%s: calloc", __func__);

	memcpy(hostname, ptr, len);

	log_debug("%s: received resolve request for %s %s", __func__, hostname,
	    af == AF_INET ? "A" : "AAAA");

	request_type = af == AF_INET ? DNS_RR_TYPE_A : DNS_RR_TYPE_AAAA;

	res = ub_resolve_async(env->sc_ub_ctx, hostname, request_type,
	    DNS_CLASS_IN, hostname, forwarder_ub_resolve_async_cb, NULL);
	if (res != 0) {
		log_errorx("%s: ub_resolve_async failed: %s", __func__,
		    ub_strerror(res));

		iov[0].iov_base = &af;
		iov[0].iov_len = sizeof(af);
		iovcnt++;

		hostname_len = strlen(hostname);
		iov[1].iov_base = &hostname_len;
		iov[1].iov_len = sizeof(hostname_len);
		iovcnt++;
		iov[2].iov_base = hostname;
		iov[2].iov_len = hostname_len;
		iovcnt++;

		proc_composev(&env->sc_ps, PROC_PARENT, IMSG_RESOLVEREQ_FAIL,
		    iov, iovcnt);
		free(hostname);
	}
}

void
forwarder_ub_ctx_init(struct pfresolved *env)
{
	struct ub_ctx		*ctx;
	int			 res, i;

	if ((ctx = ub_ctx_create()) == NULL)
		fatalx("%s: ub_ctx_create failed", __func__);

	env->sc_ub_ctx = ctx;

	/* use threads instead of fork(2) */
	if ((res = ub_ctx_async(ctx, 1)) != 0)
		fatalx("%s: ub_ctx_async failed: %s", __func__,
		    ub_strerror(res));

	/*
	 * If all hosts are considered down by libunbound it would stop sending
	 * queries until these hosts expire from the infrastructure cache. We
	 * enable infra-keep-probing to keep sending probe queries to these
	 * hosts so we can detect healthy hosts more quickly.
	 */
	if ((res = ub_ctx_set_option(ctx, "infra-keep-probing:", "yes")) != 0)
		fatalx("%s: ub_ctx_set_option infra-keep-probing failed: %s",
		    __func__, ub_strerror(res));

	/*
	 * We don't want libunbound to interfere with when queries are
	 * actually being sent so we have to disable the cache.
	 */
	if ((res = ub_ctx_set_option(ctx, "msg-cache-size:", "0")) != 0)
		fatalx("%s: ub_ctx_set_option msg-cache-size failed: %s",
		    __func__, ub_strerror(res));
	if ((res = ub_ctx_set_option(ctx, "rrset-cache-size:", "0")) != 0)
		fatalx("%s: ub_ctx_set_option rrset-cache-size failed: %s",
		    __func__, ub_strerror(res));
	if ((res = ub_ctx_set_option(ctx, "key-cache-size:", "0")) != 0)
		fatalx("%s: ub_ctx_set_option key-cache-size failed: %s",
		    __func__, ub_strerror(res));
	if ((res = ub_ctx_set_option(ctx, "neg-cache-size:", "0")) != 0)
		fatalx("%s: ub_ctx_set_option neg-cache-size failed: %s",
		    __func__, ub_strerror(res));

	if (env->sc_outbound_ip && (res = ub_ctx_set_option(ctx,
	    "outgoing-interface:", env->sc_outbound_ip)) != 0)
		fatalx("%s: ub_ctx_set_option outgoing-ip failed: %s", __func__,
		    ub_strerror(res));

	for (i = 0; i < env->sc_num_resolvers; i++) {
		if ((res = ub_ctx_set_fwd(ctx, env->sc_resolvers[i])) != 0)
			fatalx("%s: ub_ctx_set_fwd failed: %s", __func__,
			    ub_strerror(res));
	}

	if (env->sc_use_dot) {
		if ((res = ub_ctx_set_tls(ctx, 1)) != 0)
			fatalx("%s: ub_ctx_set_tls failed: %s", __func__,
			    ub_strerror(res));

		/* include root certs from /etc/ssl/cert.pem */
		if ((res = ub_ctx_set_option(ctx, "tls-system-cert:", "yes")) != 0)
			fatalx("%s: ub_ctx_set_option tls-system-cert failed: %s",
			    __func__, ub_strerror(res));

		if (env->sc_cert_bundle && (res = ub_ctx_set_option(ctx,
		    "tls-cert-bundle:", env->sc_cert_bundle)) != 0)
			fatalx("%s: ub_ctx_set_option tls-cert-bundle failed: %s",
			    __func__, ub_strerror(res));
	}

	if (env->sc_dnssec_level > DNSSEC_NONE) {
		if (!env->sc_trust_anchor)
			fatalx("DNSSEC requires a configured trust anchor");

		if ((res = ub_ctx_add_ta_file(ctx, env->sc_trust_anchor)) != 0)
			fatalx("%s: ub_ctx_add_ta_file failed: %s", __func__,
			    ub_strerror(res));
	}
}

void
forwarder_ub_fd_read_cb(int fd, short event, void *arg)
{
	struct pfresolved	*env = arg;

	ub_process(env->sc_ub_ctx);
}

void
forwarder_ub_resolve_async_cb(void *arg, int err, struct ub_result *result)
{
	struct pfresolved		*env = pfresolved_env;
	char				*hostname = arg;
	sa_family_t			 af;
	int				 hostname_len, num_addresses = 0;
	struct pfresolved_address	*addresses = NULL;
	struct iovec			 iov[6];
	int				 iovcnt = 0;
	int				 fail = 0, type;

	log_debug("%s: result for %s: qtype: %d, qclass: %d, rcode: %d, "
	    "canonname: %s, havedata: %d, nxdomain: %d, secure: %d, bogus: %d, "
	    "why_bogus: %s, was_ratelimited: %d, ttl: %d", __func__, hostname,
	    result->qtype, result->qclass, result->rcode,
	    result->canonname ? result->canonname : "NULL", result->havedata,
	    result->nxdomain, result->secure, result->bogus,
	    result->why_bogus ? result->why_bogus : "NULL",
	    result->was_ratelimited, result->ttl);

	af = result->qtype == DNS_RR_TYPE_A ? AF_INET : AF_INET6;
	iov[0].iov_base = &af;
	iov[0].iov_len = sizeof(af);
	iovcnt++;

	hostname_len = strlen(hostname);
	iov[1].iov_base = &hostname_len;
	iov[1].iov_len = sizeof(hostname_len);
	iovcnt++;
	iov[2].iov_base = hostname;
	iov[2].iov_len = hostname_len;
	iovcnt++;

	if (result->bogus) {
		log_warn("%s: DNSSEC validation for %s (%s) failed: %s",
		    __func__, hostname,
		    result->qtype == DNS_RR_TYPE_A ? "A" : "AAAA",
		    result->why_bogus);
		if (env->sc_dnssec_level >= DNSSEC_VALIDATE) {
			fail = 1;
			goto done;
		}
	}

	if (result->rcode != DNS_RCODE_NOERROR &&
	    result->rcode != DNS_RCODE_NXDOMAIN) {
		log_warn("%s: query for %s (%s) failed with rcode: %d",
		    __func__, hostname,
		    result->qtype == DNS_RR_TYPE_A ? "A" : "AAAA",
		    result->rcode);
		fail = 1;
		goto done;
	}

	if (!result->secure && env->sc_dnssec_level >= DNSSEC_FORCE) {
		log_warn("%s: DNSSEC required but not available for %s (%s)",
		    __func__, hostname,
		    result->qtype == DNS_RR_TYPE_A ? "A" : "AAAA");
		fail = 1;
		goto done;
	}

	iov[3].iov_base = &result->ttl;
	iov[3].iov_len = sizeof(result->ttl);
	iovcnt++;

	if (result->nxdomain) {
		log_notice("%s: query for %s (%s) returned NXDOMAIN", __func__,
		    hostname, result->qtype == DNS_RR_TYPE_A ? "A" : "AAAA");
		goto done;
	}

	if (!result->havedata || !result->data[0]) {
		log_info("%s: query for %s (%s) returned no data", __func__,
		    hostname, result->qtype == DNS_RR_TYPE_A ? "A" : "AAAA");
		goto done;
	}

	while (result->data[num_addresses] != NULL) {
		if ((addresses = recallocarray(addresses, num_addresses,
		    num_addresses + 1, sizeof(*addresses))) == NULL)
			fatal("%s: recallocarray", __func__);

		if (af == AF_INET) {
			if (sizeof(addresses[num_addresses].pfa_addr.in4) !=
			    result->len[num_addresses]) {
				log_errorx("query for %s (%s): data size mismatch in result",
				hostname,
				result->qtype == DNS_RR_TYPE_A ? "A" : "AAAA");
				fail = 1;
				goto done;
			}
			memcpy(&addresses[num_addresses].pfa_addr.in4,
			    result->data[num_addresses],
			    result->len[num_addresses]);
			addresses[num_addresses].pfa_af = AF_INET;
			addresses[num_addresses].pfa_prefixlen = 32;
		} else {
			if (sizeof(addresses[num_addresses].pfa_addr.in6) !=
			    result->len[num_addresses]) {
				log_errorx("query for %s (%s): data size mismatch in result",
				hostname,
				result->qtype == DNS_RR_TYPE_A ? "A" : "AAAA");
				fail = 1;
				goto done;
			}
			memcpy(&addresses[num_addresses].pfa_addr.in6,
			    result->data[num_addresses],
			    result->len[num_addresses]);
			addresses[num_addresses].pfa_af = AF_INET6;
			addresses[num_addresses].pfa_prefixlen = 128;
		}

		log_debug("%s: query for %s (%s): address %d: %s", __func__,
		    hostname, result->qtype == DNS_RR_TYPE_A ? "A" : "AAAA",
		    num_addresses, print_address(&addresses[num_addresses]));

		num_addresses++;
	}

	iov[4].iov_base = &num_addresses;
	iov[4].iov_len = sizeof(num_addresses);
	iovcnt++;
	iov[5].iov_base = addresses;
	iov[5].iov_len = num_addresses * sizeof(*addresses);
	iovcnt++;

done:
	type = fail ? IMSG_RESOLVEREQ_FAIL : IMSG_RESOLVEREQ_SUCCESS;
	proc_composev(&env->sc_ps, PROC_PARENT, type, iov, iovcnt);

	free(hostname);
	free(addresses);
	ub_resolve_free(result);
}

void
forwarder_ub_resolve_async_cb_discard(void *arg, int err, struct ub_result *result)
{
	ub_resolve_free(result);
}

