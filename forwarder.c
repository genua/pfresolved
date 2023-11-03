/*
 * Copyright (c) 2023 genua GmbH
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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

struct resolve_args {
	char		*hostname;
	sa_family_t	 af;
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

	if (pledge("stdio dns inet rpath", NULL) == -1)
		fatal("%s: pledge", __func__);

	if ((fd = ub_fd(env->sc_ub_ctx)) == -1)
		fatalx("%s: ub_fd failed", __func__);

	event_set(&env->sc_ub_fd_event, fd, EV_READ | EV_PERSIST,
	    forwarder_ub_fd_read_cb, env);
	event_add(&env->sc_ub_fd_event, NULL);

	p->p_shutdown = forwarder_shutdown;
}

void
forwarder_shutdown(void)
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
	struct resolve_args		*resolve_args;
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

	if ((resolve_args = calloc(1, sizeof(*resolve_args))) == NULL)
		fatal("%s: calloc", __func__);
	resolve_args->hostname = hostname;
	resolve_args->af = af;

	res = ub_resolve_async(env->sc_ub_ctx, hostname, request_type,
	    DNS_CLASS_IN, resolve_args, forwarder_ub_resolve_async_cb, NULL);
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
		free(resolve_args);
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

	if (!env->sc_no_daemon && (res = ub_ctx_set_option(ctx, "use-syslog:",
	    "yes")) != 0)
		fatalx("%s: ub_ctx_set_option use-syslog failed: %s", __func__,
		    ub_strerror(res));

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
	struct resolve_args		*resolve_args = arg;
	char				*hostname;
	char				*qtype_str;
	sa_family_t			 af;
	int				 hostname_len;
	int				 num_addresses = 0, max_addresses = 0;
	struct pfresolved_address	*addresses = NULL;
	struct iovec			 iov[6];
	int				 iovcnt = 0, imsg_data_size = 0;
	int				 fail = 0, type;

	hostname = resolve_args->hostname;
	af = resolve_args->af;

	qtype_str = af == AF_INET ? "A" : "AAAA";

	iov[iovcnt].iov_base = &af;
	iov[iovcnt].iov_len = sizeof(af);
	imsg_data_size += sizeof(af);
	iovcnt++;

	hostname_len = strlen(hostname);
	iov[iovcnt].iov_base = &hostname_len;
	iov[iovcnt].iov_len = sizeof(hostname_len);
	imsg_data_size += sizeof(hostname_len);
	iovcnt++;
	iov[iovcnt].iov_base = hostname;
	iov[iovcnt].iov_len = hostname_len;
	imsg_data_size += hostname_len;
	iovcnt++;

	if (err != 0) {
		log_errorx("%s: query for %s (%s) failed: %s", __func__,
		    hostname, qtype_str, ub_strerror(err));
		fail = 1;
		goto done;
	}

	log_debug("%s: result for %s (%s): qtype: %d, qclass: %d, rcode: %d, "
	    "canonname: %s, havedata: %d, nxdomain: %d, secure: %d, bogus: %d, "
	    "why_bogus: %s, was_ratelimited: %d, ttl: %d", __func__, hostname,
	    qtype_str, result->qtype, result->qclass, result->rcode,
	    result->canonname ? result->canonname : "NULL", result->havedata,
	    result->nxdomain, result->secure, result->bogus,
	    result->why_bogus ? result->why_bogus : "NULL",
	    result->was_ratelimited, result->ttl);

	if (result->bogus) {
		log_warn("%s: DNSSEC validation for %s (%s) failed: %s",
		    __func__, hostname, qtype_str, result->why_bogus);
		if (env->sc_dnssec_level >= DNSSEC_VALIDATE) {
			fail = 1;
			goto done;
		}
	}

	switch (result->rcode) {
		case DNS_RCODE_NOERROR:
		case DNS_RCODE_NXDOMAIN:
			break;
		default:
			log_warn("%s: query for %s (%s) failed with rcode: %d",
			    __func__, hostname, qtype_str, result->rcode);
			fail = 1;
			goto done;
	}

	if (!result->secure && env->sc_dnssec_level >= DNSSEC_FORCE) {
		log_warn("%s: DNSSEC required but not available for %s (%s)",
		    __func__, hostname, qtype_str);
		fail = 1;
		goto done;
	}

	iov[iovcnt].iov_base = &result->ttl;
	iov[iovcnt].iov_len = sizeof(result->ttl);
	imsg_data_size += sizeof(result->ttl);
	iovcnt++;

	if (result->nxdomain) {
		log_notice("%s: query for %s (%s) returned NXDOMAIN", __func__,
		    hostname, qtype_str);
		goto done;
	}

	if (!result->havedata || !result->data[0]) {
		log_info("%s: query for %s (%s) returned no data", __func__,
		    hostname, qtype_str);
		goto done;
	}

	max_addresses = (MAX_IMSGSIZE - IMSG_HEADER_SIZE - imsg_data_size -
	    sizeof(num_addresses)) / sizeof(*addresses);

	while (result->data[num_addresses] != NULL) {
		if (num_addresses == max_addresses) {
			log_warn("%s: query for %s (%s): maximum of %d addresses"
			    " exceeded, discarding remaining addresses",
			    __func__, hostname, qtype_str, max_addresses);
			break;
		}

		if ((addresses = recallocarray(addresses, num_addresses,
		    num_addresses + 1, sizeof(*addresses))) == NULL)
			fatal("%s: recallocarray", __func__);

		if (af == AF_INET) {
			if (sizeof(addresses[num_addresses].pfa_addr.in4) !=
			    result->len[num_addresses]) {
				log_errorx("%s: query for %s (A): data size "
				    "mismatch in result", __func__, hostname);
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
				log_errorx("%s: query for %s (AAAA): data size "
				    "mismatch in result", __func__, hostname);
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
		    hostname, qtype_str, num_addresses,
		    print_address(&addresses[num_addresses]));

		num_addresses++;
	}

	iov[iovcnt].iov_base = &num_addresses;
	iov[iovcnt].iov_len = sizeof(num_addresses);
	iovcnt++;
	iov[iovcnt].iov_base = addresses;
	iov[iovcnt].iov_len = num_addresses * sizeof(*addresses);
	iovcnt++;

done:
	type = fail ? IMSG_RESOLVEREQ_FAIL : IMSG_RESOLVEREQ_SUCCESS;
	proc_composev(&env->sc_ps, PROC_PARENT, type, iov, iovcnt);

	free(hostname);
	free(resolve_args);
	free(addresses);
	ub_resolve_free(result);
}

void
forwarder_ub_resolve_async_cb_discard(void *arg, int err, struct ub_result *result)
{
	ub_resolve_free(result);
}

