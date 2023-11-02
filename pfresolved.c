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

#include <fcntl.h>
#include <getopt.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "pfresolved.h"

__dead void usage(void);

void	 parent_shutdown(struct pfresolved *);
void	 parent_sig_handler(int, short, void *);
int	 parent_dispatch_forwarder(int, struct privsep_proc *, struct imsg *);
void	 parent_configure(struct pfresolved *);
void	 parent_reload(struct pfresolved *);
void	 parent_start_resolve_timeouts(struct pfresolved *);
void	 parent_send_resolve_request_v4(struct pfresolved *, void *);
void	 parent_send_resolve_request_v6(struct pfresolved *, void *);
void	 parent_send_resolve_request(struct pfresolved *, sa_family_t,
	     struct pfresolved_host *);
void	 parent_process_resolve_result(struct pfresolved *, struct imsg *);
struct pfresolved_host *
	 parent_get_resolve_result_data(struct pfresolved *, struct imsg *,
	     sa_family_t *, int *, int *, struct pfresolved_address **);
int	 parent_address_cmp(const void *, const void *);
void	 parent_update_host_addresses(struct pfresolved *,
	     struct pfresolved_host *, struct pfresolved_address *, int,
	     sa_family_t);
void	 parent_add_table_entries(struct pfresolved *,
	     struct pfresolved_host *, struct pfresolved_address *);
void	 parent_remove_table_entries(struct pfresolved *,
	     struct pfresolved_host *, struct pfresolved_address *);
int	 parent_init_pftables(struct pfresolved *);
void	 parent_clear_pftables(struct pfresolved *);
void	 parent_write_hints_file(struct pfresolved *);

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif
#define CLAMP(x, low, high) (MIN(high, MAX(low, x)))

struct pfresolved	*pfresolved_env;

static struct privsep_proc procs[] = {
	{ "forwarder", PROC_FORWARDER, parent_dispatch_forwarder, forwarderproc }
};

__dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-dnTv] [-f file] [-r resolver] "
	    "[-C cert_bundle_file] [-S dnssec_level] [-A trust_anchor_file] "
	    "[-i outbound_ip] [-h hints_file] [-m seconds] [-M seconds]\n",
	    __progname);
	exit(1);
}

int
main(int argc, char **argv)
{
	int			 c;
	int			 debug = 0, verbose = 0, no_action = 0;
	int			 use_dot = 0;
	int			 min_ttl = MIN_TTL_DEFAULT;
	int			 max_ttl = MAX_TTL_DEFAULT;
	int			 num_resolvers = 0;
	const char		*conffile = PFRESOLVED_CONFIG;
	const char		*errstr, *title = NULL;
	const char		*outbound_ip = NULL;
	const char		*cert_bundle = NULL, *trust_anchor = NULL;
	const char		*hints_file = NULL;
	const char	       **resolvers = NULL;
	enum dnssec_level	 dnssec_level = DNSSEC_NONE;
	struct pfresolved	*env = NULL;
	struct privsep		*ps;
	enum privsep_procid	 proc_id = PROC_PARENT;
	int			 proc_instance = 0;
	int			 argc0 = argc;

	log_init(1, LOG_DAEMON);

	while ((c = getopt(argc, argv, "A:C:df:h:i:I:m:M:nP:r:S:Tv")) != -1) {
		switch (c) {
		case 'A':
			trust_anchor = optarg;
			break;
		case 'C':
			cert_bundle = optarg;
			break;
		case 'd':
			debug++;
			break;
		case 'f':
			conffile = optarg;
			break;
		case 'h':
			hints_file = optarg;
			break;
		case 'i':
			outbound_ip = optarg;
			break;
		case 'I':
			proc_instance = strtonum(optarg, 0,
			    PROC_MAX_INSTANCES, &errstr);
			if (errstr)
				fatalx("invalid process instance");
			break;
		case 'm':
			min_ttl = strtonum(optarg, 0, INT_MAX, &errstr);
			if (errstr)
				fatalx("invalid min ttl");
			break;
		case 'M':
			max_ttl = strtonum(optarg, 0, INT_MAX, &errstr);
			if (errstr)
				fatalx("invalid max ttl");
			break;
		case 'n':
			no_action = 1;
			break;
		case 'P':
			title = optarg;
			proc_id = proc_getid(procs, nitems(procs), title);
			if (proc_id == PROC_MAX)
				fatalx("invalid process name");
			break;
		case 'r':
			if ((resolvers = recallocarray(resolvers, num_resolvers,
			    num_resolvers + 1, sizeof(*resolvers))) == NULL)
				fatal("recallocarray");
			resolvers[num_resolvers] = optarg;
			num_resolvers++;
			break;
		case 'S':
			dnssec_level = strtonum(optarg, 0, DNSSEC_FORCE,
			    &errstr);
			if (errstr)
				fatalx("invalid dnssec level");
			break;
		case 'T':
			use_dot = 1;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	if (argc > 0)
		usage();

	if ((env = calloc(1, sizeof(*env))) == NULL)
		fatal("calloc: env");

	pfresolved_env = env;
	ps = &env->sc_ps;
	ps->ps_env = env;

	env->sc_no_daemon = debug;
	env->sc_hints_file = hints_file;
	env->sc_min_ttl = min_ttl;
	env->sc_max_ttl = max_ttl;
	env->sc_outbound_ip = outbound_ip;
	env->sc_resolvers = resolvers;
	env->sc_num_resolvers = num_resolvers;
	env->sc_use_dot = use_dot;
	env->sc_cert_bundle = cert_bundle;
	env->sc_dnssec_level = dnssec_level;
	env->sc_trust_anchor = trust_anchor;

	RB_INIT(&env->sc_tables);
	RB_INIT(&env->sc_hosts);

	if (strlcpy(env->sc_conffile, conffile, PATH_MAX) >= PATH_MAX)
		fatalx("config file exceeds PATH_MAX");

	if ((ps->ps_pw = getpwnam(PFRESOLVED_USER)) == NULL)
		fatalx("unknown user %s", PFRESOLVED_USER);

	log_init(debug, LOG_DAEMON);
	log_setverbose(verbose);

	ps->ps_noaction = no_action;
	ps->ps_instance = proc_instance;
	if (title != NULL)
		ps->ps_title[proc_id] = title;
	log_pri(LOG_NOTICE, "%s starting", title ? title : "parent");

	/* only the parent returns */
	proc_init(ps, procs, nitems(procs), debug, argc0, argv, proc_id);

	setproctitle("parent");
	log_procinit("parent");

	event_init();

	signal_set(&ps->ps_evsigint, SIGINT, parent_sig_handler, ps);
	signal_set(&ps->ps_evsigterm, SIGTERM, parent_sig_handler, ps);
	signal_set(&ps->ps_evsigchld, SIGCHLD, parent_sig_handler, ps);
	signal_set(&ps->ps_evsighup, SIGHUP, parent_sig_handler, ps);
	signal_set(&ps->ps_evsigpipe, SIGPIPE, parent_sig_handler, ps);
	signal_set(&ps->ps_evsigusr1, SIGUSR1, parent_sig_handler, ps);

	signal_add(&ps->ps_evsigint, NULL);
	signal_add(&ps->ps_evsigterm, NULL);
	signal_add(&ps->ps_evsigchld, NULL);
	signal_add(&ps->ps_evsighup, NULL);
	signal_add(&ps->ps_evsigpipe, NULL);
	signal_add(&ps->ps_evsigusr1, NULL);

	proc_connect(ps);

	parent_configure(env);
	parent_start_resolve_timeouts(env);

	event_dispatch();

	proc_collect_children(ps);

	parent_shutdown(env);

	return (0);
}

void
parent_shutdown(struct pfresolved *env)
{
	proc_kill(&env->sc_ps);

	parent_clear_pftables(env);

	close(env->sc_pf_device);

	log_warn("parent terminating");

	exit(0);
}

void
parent_sig_handler(int sig, short event, void *arg)
{
	struct privsep	*ps = arg;

	switch (sig) {
	case SIGHUP:
		log_info("%s: reload requested with SIGHUP", __func__);
		parent_reload(ps->ps_env);
		parent_write_hints_file(ps->ps_env);
		break;
	case SIGUSR1:
		parent_write_hints_file(ps->ps_env);
		break;
	case SIGPIPE:
		log_info("%s: ignoring SIGPIPE", __func__);
		break;
	case SIGINT:
	case SIGTERM:
		parent_write_hints_file(ps->ps_env);
		/* FALLTHROUGH */
	case SIGCHLD:
		parent_shutdown(ps->ps_env);
		break;
	}
}

int
parent_dispatch_forwarder(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	struct pfresolved		*env = pfresolved_env;

	switch (imsg->hdr.type) {
	case IMSG_RESOLVEREQ_SUCCESS:
	case IMSG_RESOLVEREQ_FAIL:
		parent_process_resolve_result(env, imsg);
		break;
	default:
		return (-1);
	}

	return (0);
}

void
parent_configure(struct pfresolved *env)
{
	if ((parse_config(env->sc_conffile, env)) == -1) {
		proc_kill(&env->sc_ps);
		fatalx("parsing configuration failed");
	}

	if (env->sc_ps.ps_noaction) {
		log_pri(LOG_INFO, "configuration OK");
		proc_kill(&env->sc_ps);
		exit(0);
	}

	if ((env->sc_pf_device = open(PF_DEVICE_PATH, O_RDWR)) == -1) {
		proc_kill(&env->sc_ps);
		fatal("opening pf device failed");
	}

	if (pledge("stdio pf rpath wpath cpath", NULL) == -1)
		fatal("%s: pledge", __func__);

	if (parent_init_pftables(env) == -1)
		fatalx("%s: failed to init pf tables", __func__);
}

void
parent_reload(struct pfresolved *env)
{
	struct pfresolved_host		*host, *tmp_host;
	struct pfresolved_table_ref	*ref, *tmp_ref;
	struct pfresolved_table		*table, *tmp_table;
	struct pfresolved_table_entry	*entry, *tmp_entry;

	RB_FOREACH_SAFE(host, pfresolved_hosts, &env->sc_hosts, tmp_host) {
		timer_del(env, &host->pfh_timer_v4);
		timer_del(env, &host->pfh_timer_v6);

		RB_FOREACH_SAFE(ref, pfresolved_table_refs, &host->pfh_tables,
		    tmp_ref) {
			RB_REMOVE(pfresolved_table_refs, &host->pfh_tables, ref);
			free(ref);
		}

		free(host->pfh_addresses_v4);
		free(host->pfh_addresses_v6);

		RB_REMOVE(pfresolved_hosts, &env->sc_hosts, host);
		free(host);
	}

	parent_clear_pftables(env);

	RB_FOREACH_SAFE(table, pfresolved_tables, &env->sc_tables, tmp_table) {
		RB_FOREACH_SAFE(entry, pfresolved_table_entries,
		    &table->pft_entries, tmp_entry) {
			RB_REMOVE(pfresolved_table_entries, &table->pft_entries,
			    entry);
			free(entry);
		}

		RB_REMOVE(pfresolved_tables, &env->sc_tables, table);
		free(table);
	}

	if (parse_config(env->sc_conffile, env) == -1) {
		log_errorx("%s: failed to load config file %s", __func__,
		    env->sc_conffile);
	}

	if (parent_init_pftables(env) == -1)
		log_warn("%s: failed to init pf tables", __func__);

	parent_start_resolve_timeouts(env);
}

void
parent_start_resolve_timeouts(struct pfresolved *env)
{
	struct pfresolved_host		*host;

	log_info("%s: starting resolve timeouts", __func__);

	RB_FOREACH(host, pfresolved_hosts, &env->sc_hosts) {
		timer_set(env, &host->pfh_timer_v4,
		    parent_send_resolve_request_v4, host);
		timer_add(env, &host->pfh_timer_v4, 2);
		timer_set(env, &host->pfh_timer_v6,
		    parent_send_resolve_request_v6, host);
		timer_add(env, &host->pfh_timer_v6, 2);
	}
}

void
parent_send_resolve_request_v4(struct pfresolved *env, void *arg)
{
	struct pfresolved_host		*host = arg;

	parent_send_resolve_request(env, AF_INET, host);
}

void
parent_send_resolve_request_v6(struct pfresolved *env, void *arg)
{
	struct pfresolved_host		*host = arg;

	parent_send_resolve_request(env, AF_INET6, host);
}

void
parent_send_resolve_request(struct pfresolved *env, sa_family_t af,
    struct pfresolved_host *host)
{
	struct iovec		 iov[2];
	int			 iovcnt = 0;

	log_debug("%s: sending resolve request for %s (%s) to forwarder",
	    __func__, host->pfh_hostname, af == AF_INET ? "A" : "AAAA");

	iov[0].iov_base = &af;
	iov[0].iov_len = sizeof(af);
	iovcnt++;
	iov[1].iov_base = host->pfh_hostname;
	iov[1].iov_len = strlen(host->pfh_hostname);
	iovcnt++;

	proc_composev(&env->sc_ps, PROC_FORWARDER, IMSG_RESOLVEREQ, iov, iovcnt);
}

void
parent_process_resolve_result(struct pfresolved *env, struct imsg *imsg)
{
	int				 ttl = 0, num_addresses = 0;
	int				 timeout = 0, shift = 0;
	sa_family_t			 af = AF_INET;
	struct pfresolved_host		*host;
	struct pfresolved_address	*addresses = NULL;
	struct pfresolved_table_ref	*table_ref;

	host = parent_get_resolve_result_data(env, imsg, &af, &ttl,
	    &num_addresses, &addresses);
	if (host == NULL)
		return;

	if (imsg->hdr.type == IMSG_RESOLVEREQ_FAIL) {
		log_warn("%s: resolve request for %s (%s) failed", __func__,
		    host->pfh_hostname, af == AF_INET ? "A" : "AAAA");

		if (af == AF_INET) {
			shift = MIN(host->pfh_tries_v4, 30);
			host->pfh_tries_v4++;
		} else {
			shift = MIN(host->pfh_tries_v6, 30);
			host->pfh_tries_v6++;
		}
		timeout = RETRY_TIMEOUT_BASE + (1 << shift);
		if (timeout > RETRY_TIMEOUT_MAX)
			timeout = RETRY_TIMEOUT_MAX;

		goto done;
	}

	parent_update_host_addresses(env, host, addresses, num_addresses, af);

	if (af == AF_INET) {
		host->pfh_tries_v4 = 0;
	} else {
		host->pfh_tries_v6 = 0;
	}

	RB_FOREACH(table_ref, pfresolved_table_refs, &host->pfh_tables) {
		pftable_set_addresses(env, table_ref->pftr_table);
	}

	/*
	 * Set the timeout to be 1 second higher than the ttl to try to prevent
	 * getting a response with ttl 0.
	 */
	timeout = CLAMP(ttl + 1, env->sc_min_ttl, env->sc_max_ttl);

done:
	log_info("%s: starting new resolve request for %s (%s) in %d seconds",
	    __func__, host->pfh_hostname, af == AF_INET ? "A" : "AAAA", timeout);
	if (af == AF_INET) {
		timer_add(env, &host->pfh_timer_v4, timeout);
	} else {
		timer_add(env, &host->pfh_timer_v6, timeout);
	}
}

struct pfresolved_host *
parent_get_resolve_result_data(struct pfresolved *env, struct imsg *imsg,
    sa_family_t *af, int *ttl, int *num_addresses,
    struct pfresolved_address **addresses)
{
	uint8_t				*ptr;
	size_t				 len;
	int				 hostname_len;
	struct pfresolved_host		 search_key, *host;

	bzero(&search_key, sizeof(search_key));

	ptr = imsg->data;
	len = IMSG_DATA_SIZE(imsg);

	if (len < sizeof(*af))
		fatalx("%s: imsg length too small", __func__);

	memcpy(af, ptr, sizeof(*af));
	ptr += sizeof(*af);
	len -= sizeof(*af);

	if (len < sizeof(hostname_len))
		fatalx("%s: imsg length too small", __func__);

	memcpy(&hostname_len, ptr, sizeof(hostname_len));
	ptr += sizeof(hostname_len);
	len -= sizeof(hostname_len);

	if (hostname_len < 0 || len < (size_t)hostname_len)
		fatalx("%s: imsg length too small", __func__);

	memcpy(search_key.pfh_hostname, ptr, hostname_len);
	ptr += hostname_len;
	len -= hostname_len;

	host = RB_FIND(pfresolved_hosts, &env->sc_hosts, &search_key);
	if (host == NULL) {
		log_errorx("%s: host from resolve result not found: %s",
		    __func__, search_key.pfh_hostname);
		return (NULL);
	}

	if (imsg->hdr.type == IMSG_RESOLVEREQ_FAIL)
		return (host);

	if (len < sizeof(*ttl))
		fatalx("%s: imsg length too small", __func__);

	memcpy(ttl, ptr, sizeof(*ttl));
	ptr += sizeof(*ttl);
	len -= sizeof(*ttl);

	if (len == 0)
		return (host);

	if (len < sizeof(*num_addresses))
		fatalx("%s: imsg length too small", __func__);

	memcpy(num_addresses, ptr, sizeof(*num_addresses));
	ptr += sizeof(*num_addresses);
	len -= sizeof(*num_addresses);

	if (len != *num_addresses * sizeof(**addresses))
		fatalx("%s: bad length imsg", __func__);

	if ((*addresses = calloc(*num_addresses, sizeof(**addresses))) == NULL)
		fatal("%s: calloc", __func__);

	memcpy(*addresses, ptr, *num_addresses * sizeof(**addresses));

	return (host);
}

int
parent_address_cmp(const void *a, const void *b)
{
	return address_cmp((const struct pfresolved_address *)a,
	    (const struct pfresolved_address *)b);
}

void
parent_update_host_addresses(struct pfresolved *env,
    struct pfresolved_host *host, struct pfresolved_address *addresses,
    int num_addresses, sa_family_t af)
{
	int				 cur_old = 0, num_old, cur_new = 0, cmp;
	struct pfresolved_address	*old_addresses;
	char				*addrs_str = NULL;
	char				*added_addrs_str = NULL;
	char				*removed_addrs_str = NULL;

	if (af == AF_INET) {
		old_addresses = host->pfh_addresses_v4;
		num_old = host->pfh_num_addresses_v4;
	} else {
		old_addresses = host->pfh_addresses_v6;
		num_old = host->pfh_num_addresses_v6;
	}

	if (num_addresses > 0)
		qsort(addresses, num_addresses, sizeof(*addresses),
		    parent_address_cmp);

	/*
	 * The old addresses have already been sorted when they were previously
	 * assigned to the host.
	 */

	while (cur_old < num_old && cur_new < num_addresses) {
		cmp = address_cmp(&old_addresses[cur_old], &addresses[cur_new]);

		if (cmp == 0) {
			appendf(&addrs_str, "%s%s",
			    addrs_str == NULL ? "" : ", ",
			    print_address(&addresses[cur_new]));

			cur_old++;
			cur_new++;
		} else if (cmp < 0) {
			appendf(&removed_addrs_str, "%s%s",
			    removed_addrs_str == NULL ? "" : ", ",
			    print_address(&old_addresses[cur_old]));
			parent_remove_table_entries(env, host,
			    &old_addresses[cur_old]);

			cur_old++;
		} else {
			appendf(&addrs_str, "%s%s",
			    addrs_str == NULL ? "" : ", ",
			    print_address(&addresses[cur_new]));
			appendf(&added_addrs_str, "%s%s",
			    added_addrs_str == NULL ? "" : ", ",
			    print_address(&addresses[cur_new]));
			parent_add_table_entries(env, host,
			    &addresses[cur_new]);

			cur_new++;
		}
	}

	while (cur_old < num_old) {
		appendf(&removed_addrs_str, "%s%s",
		    removed_addrs_str == NULL ? "" : ", ",
		    print_address(&old_addresses[cur_old]));
		parent_remove_table_entries(env, host,
		    &old_addresses[cur_old]);

		cur_old++;
	}

	while (cur_new < num_addresses) {
		appendf(&addrs_str, "%s%s",
		    addrs_str == NULL ? "" : ", ",
		    print_address(&addresses[cur_new]));
		appendf(&added_addrs_str, "%s%s",
		    added_addrs_str == NULL ? "" : ", ",
		    print_address(&addresses[cur_new]));
		parent_add_table_entries(env, host, &addresses[cur_new]);

		cur_new++;
	}

	if (af == AF_INET) {
		free(host->pfh_addresses_v4);
		host->pfh_addresses_v4 = addresses;
		host->pfh_num_addresses_v4 = num_addresses;
	} else {
		free(host->pfh_addresses_v6);
		host->pfh_addresses_v6 = addresses;
		host->pfh_num_addresses_v6 = num_addresses;
	}


	if (added_addrs_str || removed_addrs_str) {
		log_notice("%s: addresses for %s (%s) changed: addresses: %s, "
		    "added: %s, removed: %s", __func__, host->pfh_hostname,
		    af == AF_INET ? "A" : "AAAA", addrs_str ? addrs_str : "none",
		    added_addrs_str ? added_addrs_str : "none",
		    removed_addrs_str ? removed_addrs_str : "none");
	} else {
		log_info("%s: addresses for %s (%s) did not change: addresses: %s",
		    __func__, host->pfh_hostname, af == AF_INET ? "A" : "AAAA",
		    addrs_str ? addrs_str : "none");
	}

	free(addrs_str);
	free(added_addrs_str);
	free(removed_addrs_str);
}

void
parent_add_table_entries(struct pfresolved *env, struct pfresolved_host *host,
    struct pfresolved_address *address)
{
	struct pfresolved_table_ref	*table_ref;
	struct pfresolved_table_entry	*entry, search_key;

	bzero(&search_key, sizeof(search_key));

	RB_FOREACH(table_ref, pfresolved_table_refs, &host->pfh_tables) {
		search_key.pfte_addr = *address;
		entry = RB_FIND(pfresolved_table_entries,
		    &table_ref->pftr_table->pft_entries, &search_key);
		if (entry == NULL) {
			if ((entry = calloc(1, sizeof(*entry))) == NULL)
				fatal("%s: calloc", __func__);

			entry->pfte_addr = *address;
			RB_INSERT(pfresolved_table_entries,
				&table_ref->pftr_table->pft_entries, entry);
		} else if (entry->pfte_refcount < 0 ||
		    (entry->pfte_refcount == 0 && !entry->pfte_static)) {
			log_errorx("%s: entries for table %s are inconsistent: "
			    "refcount was %d before incrementing for %s (%s)",
			    __func__, table_ref->pftr_table->pft_name,
			    entry->pfte_refcount, print_address(address),
			    entry->pfte_static ? "static" : "not static");
		}
		entry->pfte_refcount++;
	}
}

void
parent_remove_table_entries(struct pfresolved *env,
    struct pfresolved_host *host, struct pfresolved_address *address)
{
	struct pfresolved_table_ref	*table_ref;
	struct pfresolved_table_entry	*old_entry, search_key;

	bzero(&search_key, sizeof(search_key));

	RB_FOREACH(table_ref, pfresolved_table_refs, &host->pfh_tables) {
		search_key.pfte_addr = *address;
		old_entry = RB_FIND(pfresolved_table_entries,
		    &table_ref->pftr_table->pft_entries, &search_key);
		if (old_entry == NULL) {
			log_errorx("%s: entries for table %s are inconsistent: "
			    "old entry not found for %s",
			    __func__, table_ref->pftr_table->pft_name,
			    print_address(address));
			continue;
		}

		if (old_entry->pfte_refcount <= 0) {
			log_errorx("%s: entries for table %s are inconsistent: "
			    "refcount was %d before decrementing for %s",
			    __func__, table_ref->pftr_table->pft_name,
			    old_entry->pfte_refcount,
			    print_address(address));
		}

		old_entry->pfte_refcount--;
		if (old_entry->pfte_refcount > 0 || old_entry->pfte_static)
			continue;

		RB_REMOVE(pfresolved_table_entries,
		    &table_ref->pftr_table->pft_entries, old_entry);
		free(old_entry);
	}
}

int
parent_init_pftables(struct pfresolved *env)
{
	struct pfresolved_table		*table;
	int				 failed = 0;

	RB_FOREACH(table, pfresolved_tables, &env->sc_tables) {
		if (pftable_set_addresses(env, table) == -1)
			failed = 1;
	}

	return (failed);
}

void
parent_clear_pftables(struct pfresolved *env)
{
	struct pfresolved_table		*table;

	RB_FOREACH(table, pfresolved_tables, &env->sc_tables) {
		pftable_clear_addresses(env, table->pft_name);
	}
}

void
parent_write_hints_file(struct pfresolved *env)
{
	FILE				*file;
	struct pfresolved_table		*table;
	struct pfresolved_host		*host;
	struct pfresolved_table_ref	*table_ref, search_key;
	int				 has_address = 0, i;

	if (!env->sc_hints_file) {
		log_info("%s: no hints file configured", __func__);
		return;
	}

	if ((file = fopen(env->sc_hints_file, "w")) == NULL) {
		log_error("%s: failed to open the hints file", __func__);
		return;
	}

	RB_FOREACH(table, pfresolved_tables, &env->sc_tables) {
		fprintf(file, "%s:\n", table->pft_name);

		RB_FOREACH(host, pfresolved_hosts, &env->sc_hosts) {
			bzero(&search_key, sizeof(search_key));
			search_key.pftr_table = table;
			table_ref = RB_FIND(pfresolved_table_refs,
			    &host->pfh_tables, &search_key);
			if (!table_ref)
				continue;

			fprintf(file, "- %s:", host->pfh_hostname);
			has_address = 0;
			for (i = 0; i < host->pfh_num_addresses_v4; i++) {
				fprintf(file, "%s %s", has_address ? "," : "",
				    print_address(&host->pfh_addresses_v4[i]));
				has_address = 1;
			}
			for (i = 0; i < host->pfh_num_addresses_v6; i++) {
				fprintf(file, "%s %s", has_address ? "," : "",
				    print_address(&host->pfh_addresses_v6[i]));
				has_address = 1;
			}
			fprintf(file, "\n");
		}

		fprintf(file, "\n");
	}

	fclose(file);
}

static __inline int
pfte_cmp(struct pfresolved_table_entry *a, struct pfresolved_table_entry *b)
{
	return (address_cmp(&a->pfte_addr, &b->pfte_addr));
}

RB_GENERATE(pfresolved_table_entries, pfresolved_table_entry, pfte_node, pfte_cmp);

static __inline int
pft_cmp(struct pfresolved_table *a, struct pfresolved_table *b)
{
	return (strcmp(a->pft_name, b->pft_name));
}

RB_GENERATE(pfresolved_tables, pfresolved_table, pft_node, pft_cmp);

static __inline int
pftr_cmp(struct pfresolved_table_ref *a, struct pfresolved_table_ref *b)
{
	return (pft_cmp(a->pftr_table, b->pftr_table));
}

RB_GENERATE(pfresolved_table_refs, pfresolved_table_ref, pftr_node, pftr_cmp);

static __inline int
pfh_cmp(struct pfresolved_host *a, struct pfresolved_host *b)
{
	return (strcmp(a->pfh_hostname, b->pfh_hostname));
}

RB_GENERATE(pfresolved_hosts, pfresolved_host, pfh_node, pfh_cmp);

