#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/pfvar.h>

#include <event.h>
#include <imsg.h>
#include <limits.h>
#include <stdarg.h>
#include <unbound.h>

#ifndef PFRESOLVED_H
#define PFRESOLVED_H

#define PFRESOLVED_USER "_pfresolved"
#define PFRESOLVED_CONFIG "/etc/pfresolved.conf"
#define PF_DEVICE_PATH "/dev/pf"

#define MIN_TTL_DEFAULT 10
#define MAX_TTL_DEFAULT 86400

/*
 * Failed queries are cached for 5 seconds by libunbound so there is no reason
 * to start with a lower base timeout.
 */
#define RETRY_TIMEOUT_BASE 5
#define RETRY_TIMEOUT_MAX 3600

/*
 * Common daemon infrastructure, local imsg etc.
 */

struct imsgev {
	struct imsgbuf		 ibuf;
	void			(*handler)(int, short, void *);
	struct event		 ev;
	struct privsep_proc	*proc;
	void			*data;
	short			 events;
	const char		*name;
};

#define IMSG_SIZE_CHECK(imsg, p) do {				\
	if (IMSG_DATA_SIZE(imsg) < sizeof(*p))			\
		fatalx("bad length imsg received");		\
} while (0)
#define IMSG_DATA_SIZE(imsg)	((imsg)->hdr.len - IMSG_HEADER_SIZE)

enum imsg_type {
	IMSG_NONE,
	IMSG_CTL_VERBOSE,
	IMSG_CTL_PROCFD,
	IMSG_RESOLVEREQ,
	IMSG_RESOLVEREQ_SUCCESS,
	IMSG_RESOLVEREQ_FAIL
};

enum privsep_procid {
	PROC_PARENT = 0,
	PROC_FORWARDER,
	PROC_MAX
};

struct privsep_pipes {
	int				*pp_pipes[PROC_MAX];
};

struct privsep {
	struct privsep_pipes		*ps_pipes[PROC_MAX];
	struct privsep_pipes		*ps_pp;

	struct imsgev			*ps_ievs[PROC_MAX];
	const char			*ps_title[PROC_MAX];
	pid_t				 ps_pid[PROC_MAX];
	struct passwd			*ps_pw;
	int				 ps_noaction;

	/* XXX: no control socket for now */
	/*struct control_sock		 ps_csock;
	struct control_socks		 ps_rcsocks;*/

	unsigned int			 ps_instances[PROC_MAX];
	unsigned int			 ps_ninstances;
	unsigned int			 ps_instance;

	/* Event and signal handlers */
	struct event			 ps_evsigint;
	struct event			 ps_evsigterm;
	struct event			 ps_evsigchld;
	struct event			 ps_evsighup;
	struct event			 ps_evsigpipe;
	struct event			 ps_evsigusr1;

	struct pfresolved		*ps_env;
};

struct privsep_proc {
	const char		*p_title;
	enum privsep_procid	 p_id;
	int			(*p_cb)(int, struct privsep_proc *,
				    struct imsg *);
	void			(*p_init)(struct privsep *,
				    struct privsep_proc *);
	const char		*p_chroot;
	struct passwd		*p_pw;
	struct privsep		*p_ps;
	void			(*p_shutdown)(void);
};

struct privsep_fd {
	enum privsep_procid		 pf_procid;
	unsigned int			 pf_instance;
};

#define PROC_PARENT_SOCK_FILENO 3
#define PROC_MAX_INSTANCES      32

extern enum privsep_procid privsep_process;

enum dnssec_level {
	DNSSEC_NONE = 0,
	DNSSEC_LOG_ONLY,
	DNSSEC_VALIDATE,
	DNSSEC_FORCE
};

struct pfresolved_timer {
	struct event		 tmr_ev;
	struct pfresolved	*tmr_env;
	void			(*tmr_cb)(struct pfresolved *, void *);
	void			*tmr_cbarg;
};

/*
 * The general data structure looks like this:
 *
 * pfresolved -------------------------------
 *    |                                     |
 *   1:n                                   1:n
 *    |                                     |
 *    v                                     v
 *   host -- 1:n --> table_ref -- 1:1 --> table
 *    |                                     |
 *   1:n                                   1:n
 *    |                                     |
 *    v            logical link             v
 * address         --- 1:n --->        table_entry
 *
 * pfresolved contains an RB_TREE of tables and an RB_TREE of hosts.
 *
 * The hosts are not directly part of a table to avoid data duplication since
 * they are allowed to be included in multiple tables. Instead the association
 * between hosts and tables is done indirectly: Each host contains an RB_TREE of
 * table refs that link to a table. Additionally, hosts contain an array of
 * addresses that is updated with each resolve.
 *
 * Each table contains an RB_TREE of table entries. These table entries contain
 * one address each that was either defined statically for that table or that
 * was the result of a DNS resolve for a host associated with this table.
 *
 * Additionally, there is a purely logical link between addresses of a host and
 * the table entries for that address. Each address of a host has a corresponding
 * table entry in all tables the host belongs to. When the addresses for a host
 * are updated by a DNS resolve the tables that this host is in and therefore
 * the corresponding table entries are also updated. The table entries keep
 * track of how many logical references there are to themselves. This is done
 * to ensure that addresses are only removed from a table when they are no
 * longer referenced by any host.
 */

struct pfresolved_address {
	sa_family_t			 pfa_af;
	union {
		struct in_addr		 in4;
		struct in6_addr		 in6;
	}				 pfa_addr;
	int				 pfa_prefixlen;
};

struct pfresolved_table_entry {
	struct pfresolved_address		 pfte_addr;
	int					 pfte_static;
	int					 pfte_negate;
	int					 pfte_refcount;
	RB_ENTRY(pfresolved_table_entry)	 pfte_node;
};
RB_HEAD(pfresolved_table_entries, pfresolved_table_entry);
RB_PROTOTYPE(pfresolved_table_entries, pfresolved_table_entry, pfte_node, pfte_cmp);

struct pfresolved_table {
	char					 pft_name[PF_TABLE_NAME_SIZE];
	struct pfresolved_table_entries		 pft_entries;
	RB_ENTRY(pfresolved_table)		 pft_node;
};
RB_HEAD(pfresolved_tables, pfresolved_table);
RB_PROTOTYPE(pfresolved_tables, pfresolved_table, pft_node, pft_cmp);

struct pfresolved_table_ref {
	struct pfresolved_table			*pftr_table;
	RB_ENTRY(pfresolved_table_ref)	 	 pftr_node;
};
RB_HEAD(pfresolved_table_refs, pfresolved_table_ref);
RB_PROTOTYPE(pfresolved_table_refs, pfresolved_table_ref, pftr_node, pftr_cmp);

struct pfresolved_host {
	char				 pfh_hostname[HOST_NAME_MAX + 1];
	struct pfresolved_table_refs	 pfh_tables;
	struct pfresolved_address	*pfh_addresses_v4;
	int				 pfh_num_addresses_v4;
	struct pfresolved_timer		 pfh_timer_v4;
	int				 pfh_tries_v4;
	struct pfresolved_address	*pfh_addresses_v6;
	int				 pfh_num_addresses_v6;
	struct pfresolved_timer		 pfh_timer_v6;
	int				 pfh_tries_v6;
	RB_ENTRY(pfresolved_host)	 pfh_node;
};
RB_HEAD(pfresolved_hosts, pfresolved_host);
RB_PROTOTYPE(pfresolved_hosts, pfresolved_host, pfh_node, pfh_cmp);

struct pfresolved {
	int					 sc_no_daemon;
	char					 sc_conffile[PATH_MAX];
	struct pfresolved_tables		 sc_tables;
	struct pfresolved_hosts			 sc_hosts;
	int					 sc_pf_device;
	int					 sc_min_ttl;
	int					 sc_max_ttl;
	const char				*sc_hints_file;
	struct privsep				 sc_ps;
	struct ub_ctx				*sc_ub_ctx;
	struct event				 sc_ub_fd_event;
	const char				*sc_outbound_ip;
	const char			       **sc_resolvers;
	int					 sc_num_resolvers;
	int					 sc_use_dot;
	const char				*sc_cert_bundle;
	enum dnssec_level			 sc_dnssec_level;
	const char				*sc_trust_anchor;
};

extern struct pfresolved	*pfresolved_env;

/* forwarder.c */
void	 forwarderproc(struct privsep *, struct privsep_proc *);

/* pftable.c */
int	 pftable_set_addresses(struct pfresolved *, struct pfresolved_table *);
int	 pftable_clear_addresses(struct pfresolved *, const char *);
int	 pftable_create_table(struct pfresolved *, const char *);

/* parse.y */
int	 parse_config(const char *, struct pfresolved *);
int	 cmdline_symset(char *);

/* timer.c */
void	 timer_set(struct pfresolved *, struct pfresolved_timer *,
	    void (*)(struct pfresolved *, void *), void *);
void	 timer_add(struct pfresolved *, struct pfresolved_timer *, int);
void	 timer_del(struct pfresolved *, struct pfresolved_timer *);

/* util.c */
const char *
	 print_address(struct pfresolved_address *);
int	 address_cmp(const struct pfresolved_address *,
	     const struct pfresolved_address *);
void	 appendf(char **, char *, ...)
	     __attribute__((__format__ (printf, 2, 3)));

/* proc.c */
void	 proc_init(struct privsep *, struct privsep_proc *, unsigned int, int,
	    int, char **, enum privsep_procid);
void	 proc_collect_children(struct privsep *);
void	 proc_kill(struct privsep *);
void	 proc_connect(struct privsep *);
void	 proc_dispatch(int, short event, void *);
void	 proc_run(struct privsep *, struct privsep_proc *,
	    struct privsep_proc *, unsigned int,
	    void (*)(struct privsep *, struct privsep_proc *, void *), void *);
void	 imsg_event_add(struct imsgev *);
int	 imsg_compose_event(struct imsgev *, uint16_t, uint32_t,
	    pid_t, int, void *, uint16_t);
int	 imsg_composev_event(struct imsgev *, uint16_t, uint32_t,
	    pid_t, int, const struct iovec *, int);
int	 proc_compose_imsg(struct privsep *, enum privsep_procid, int,
	    uint16_t, uint32_t, int, void *, uint16_t);
int	 proc_compose(struct privsep *, enum privsep_procid,
	    uint16_t, void *, uint16_t);
int	 proc_composev_imsg(struct privsep *, enum privsep_procid, int,
	    uint16_t, uint32_t, int, const struct iovec *, int);
int	 proc_composev(struct privsep *, enum privsep_procid,
	    uint16_t, const struct iovec *, int);
int	 proc_forward_imsg(struct privsep *, struct imsg *,
	    enum privsep_procid, int);
struct imsgbuf *
	 proc_ibuf(struct privsep *, enum privsep_procid, int);
struct imsgev *
	 proc_iev(struct privsep *, enum privsep_procid, int);
enum privsep_procid
	 proc_getid(struct privsep_proc *, unsigned int, const char *);
int	 proc_flush_imsg(struct privsep *, enum privsep_procid, int);

/* log.c */
void	log_init(int, int);
void	log_procinit(const char *);
void	log_setverbose(int);
int	log_getverbose(void);
void	log_error(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	log_errorx(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	log_warn(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	log_notice(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	log_info(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	log_debug(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	log_pri(int, const char *, ...)
	    __attribute__((__format__ (printf, 2, 3)));
void	logit(int, const char *, ...)
	    __attribute__((__format__ (printf, 2, 3)));
void	vlog(int, const char *, va_list)
	    __attribute__((__format__ (printf, 2, 0)));
__dead void fatal(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
__dead void fatalx(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));

#ifndef nitems
#define nitems(_a)   (sizeof((_a)) / sizeof((_a)[0]))
#endif

#endif /* PFRESOLVED_H */
