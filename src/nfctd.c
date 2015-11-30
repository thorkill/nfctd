/**
 * nfctd - netlinkfilter-conntrack net-snmp statictics
 *
 * Copyright (C) 2015 Rafal Lesniak & Markus Koetter
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <errno.h>
#include <time.h>

#include <execinfo.h>

#include <ev.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter/nf_conntrack_tcp.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <pcap/pcap.h>
#include <pcap/bpf.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "nfctd-snmp.h"
#include "lcfg_static.h"

#define IP6_HDRLEN 40  // IPv6 header length
#define TCP_HDRLEN 20  // TCP header length, excludes options data
#define UDP_HDRLEN 8
#define PKT_MAX_SIZE 256
#define ONE_MILLION 1000000

struct nfctd {
	struct lcfg *config;
	struct ev_loop *loop;
	struct nfct_handle *netlink_handle;
	struct nfctd_group *groups;
	ev_io nf_callback_watcher;
	ev_io *iow;
	ev_timer snmp_timer;
	ev_check snmp_check;
	ev_prepare snmp_prepare;
	int netlink_handle_fd;
	int snmp_numfds;
	int group_count;
	fd_set fdset;
};

struct nfctd_group {
	char *filter;
	char *label;
	int id;
	struct bpf_program *bpf;
	struct nfctd_group *next;
};

struct nfctd *g_nfctd;

volatile sig_atomic_t done = 0;

ev_signal signal_watcher;

#define MAX(a, b) \
	( {__typeof__( a )_a = ( a ); \
	   __typeof__( b )_b = ( b ); \
	   _a > _b ? _a : _b; } )

#define MIN(a, b)              \
	( {__typeof__( a )_a = ( a ); \
	   __typeof__( b )_b = ( b ); \
	   _a < _b ? _a : _b; } )

/**
 * TCP counting function
 */
void __handle_tcp_v4(struct nf_conntrack *ct, struct nfctTable_entry *entry)
{

	switch( nfct_get_attr_u8(ct, ATTR_TCP_STATE) )
	{

	case TCP_CONNTRACK_SYN_SENT:
		entry->ipv4TcpStateSynSent++;
		break;
	case TCP_CONNTRACK_SYN_RECV:
		entry->ipv4TcpStateSynRecv++;
		break;
	case TCP_CONNTRACK_ESTABLISHED:
		entry->ipv4TcpStateEstablished++;
		break;
	case TCP_CONNTRACK_FIN_WAIT:
		entry->ipv4TcpStateFinWait++;
		break;
	case TCP_CONNTRACK_LAST_ACK:
		entry->ipv4TcpStateLastAck++;
		break;
	case TCP_CONNTRACK_TIME_WAIT:
		entry->ipv4TcpStateTimeWait++;
		break;
	case TCP_CONNTRACK_CLOSE:
		entry->ipv4TcpStateClose++;
		break;
	case TCP_CONNTRACK_CLOSE_WAIT:
		entry->ipv4TcpStateCloseWait++;
		break;
	case TCP_CONNTRACK_SYN_SENT2:
		entry->ipv4TcpStateSynSentAgain++;
		break;
	case TCP_CONNTRACK_NONE:
		break;
	default:
		fprintf(stderr, "%s:%d: tcp default case (%d)\n", __FUNCTION__, __LINE__,
		        nfct_get_attr_u8(ct, ATTR_TCP_STATE) );
	}
}

/**
 * TCPv6 counting function
 */
void __handle_tcp_v6(struct nf_conntrack *ct, struct nfctTable_entry *entry)
{

	switch( nfct_get_attr_u8(ct, ATTR_TCP_STATE) )
	{

	case TCP_CONNTRACK_SYN_SENT:
		entry->ipv6TcpStateSynSent++;
		break;
	case TCP_CONNTRACK_SYN_RECV:
		entry->ipv6TcpStateSynRecv++;
		break;
	case TCP_CONNTRACK_ESTABLISHED:
		entry->ipv6TcpStateEstablished++;
		break;
	case TCP_CONNTRACK_FIN_WAIT:
		entry->ipv6TcpStateFinWait++;
		break;
	case TCP_CONNTRACK_LAST_ACK:
		entry->ipv6TcpStateLastAck++;
		break;
	case TCP_CONNTRACK_TIME_WAIT:
		entry->ipv6TcpStateTimeWait++;
		break;
	case TCP_CONNTRACK_CLOSE:
		entry->ipv6TcpStateClose++;
		break;
	case TCP_CONNTRACK_CLOSE_WAIT:
		entry->ipv6TcpStateCloseWait++;
		break;
	case TCP_CONNTRACK_SYN_SENT2:
		entry->ipv6TcpStateSynSentAgain++;
		break;
	case TCP_CONNTRACK_NONE:
		break;
	default:
		fprintf(stderr, "%s:%d: tcp default case (%d)\n", __FUNCTION__, __LINE__,
		        nfct_get_attr_u8(ct, ATTR_TCP_STATE) );
	}
}

void __l3_inet6(struct nf_conntrack *ct, struct nfctTable_entry *entry)
{
	u_int8_t l4proto;
	u_int32_t status;

	l4proto = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);
	status = nfct_get_attr_u32(ct, ATTR_STATUS);

	switch( l4proto )
	{
	case IPPROTO_TCP:
		entry->ipv6TcpCount++;

		if( status & IPS_ASSURED )
		{
			entry->ipv6TcpAssured++;
		} else
		if( !( status & IPS_SEEN_REPLY ) )
		{
			entry->ipv6TcpUnreplied++;
		} else
		{
			entry->ipv6TcpHalfAssured++;
		}

		__handle_tcp_v6(ct, entry);
		break;

	case IPPROTO_UDP:
		entry->ipv6UdpCount++;

		if( status & IPS_ASSURED )
		{
			entry->ipv6UdpAssured++;
		} else
		if( !( status & IPS_SEEN_REPLY ) )
		{
			entry->ipv6UdpUnreplied++;
		} else
		{
			entry->ipv6UdpHalfAssured++;
		}

	case IPPROTO_ICMPV6:
		entry->ipv6IcmpCount++;

		if( status & IPS_ASSURED )
		{
			entry->ipv6IcmpAssured++;
		} else
		if( !( status & IPS_SEEN_REPLY ) )
		{
			entry->ipv6IcmpUnreplied++;
		} else
		{
			entry->ipv6IcmpHalfAssured++;
		}

		break;

	default:
		fprintf(stderr, "%s:%d: default %d", __FUNCTION__, __LINE__, l4proto);
	}
}

void __l3_inet(struct nf_conntrack *ct, struct nfctTable_entry *entry)
{
	u_int8_t l4proto;
	u_int32_t status;

	l4proto = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);
	status = nfct_get_attr_u32(ct, ATTR_STATUS);

	switch( l4proto )
	{

	case IPPROTO_TCP:
		entry->ipv4TcpCount++;

		if( status & IPS_ASSURED )
		{
			entry->ipv4TcpAssured++;
		} else
		if( !( status & IPS_SEEN_REPLY ) )
		{
			entry->ipv4TcpUnreplied++;
		} else
		{
			entry->ipv4TcpHalfAssured++;
		}

		__handle_tcp_v4(ct, entry);
		break;

	case IPPROTO_UDP:
		entry->ipv4UdpCount++;

		if( status & IPS_ASSURED )
		{
			entry->ipv4UdpAssured++;
		} else
		if( !( status & IPS_SEEN_REPLY ) )
		{
			entry->ipv4UdpUnreplied++;
		} else
		{
			entry->ipv4UdpHalfAssured++;
		}

		break;

	case IPPROTO_ICMP:
		entry->ipv4IcmpCount++;

		if( status & IPS_ASSURED )
		{
			entry->ipv4IcmpAssured++;
		} else
		if( !( status & IPS_SEEN_REPLY ) )
		{
			entry->ipv4IcmpUnreplied++;
		} else
		{
			entry->ipv4IcmpHalfAssured++;
		}

		break;

	default:
		fprintf(stderr, "%s:%d: default %d", __FUNCTION__, __LINE__, l4proto);
	}
}

void increment_count_by_group_id(struct nf_conntrack *ct, struct nfctTable_entry *entry)
{
	u_int8_t l3proto;

	l3proto = nfct_get_attr_u8(ct, ATTR_ORIG_L3PROTO);

	switch( l3proto )
	{
	case AF_INET:
		__l3_inet(ct, entry);
		break;
	case AF_INET6:
		__l3_inet6(ct, entry);
		break;
	default:
		fprintf(stderr, "%s:%d : l3proto default case: %d\n", __FUNCTION__, __LINE__, l3proto);
		break;
	}
}

int nfctsa_data_cb(const struct nlmsghdr *nlh, int nf_conntrack_msg_type,  struct nf_conntrack *ct, void *data)
{
	struct nfctd_group *g;

	u_int8_t l4proto, l3proto;

	struct nfctTable_entry *entry;

	struct tcphdr *tcph;
	struct udphdr *udph;
	int len = 0;

	//Datagram to represent the packet
	char datagram[PKT_MAX_SIZE];
	memset(datagram, 0, PKT_MAX_SIZE);

	l3proto = nfct_get_attr_u8(ct, ATTR_ORIG_L3PROTO);
	l4proto = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);

	if( l3proto == AF_INET )
	{
		struct iphdr *iph = (struct iphdr *) datagram;

		//Fill in the IP Header
		iph->ihl = 5;
		iph->version = 4;
		iph->tos = 0;

		iph->check = 0;
		iph->saddr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
		iph->daddr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);

		switch( l4proto )
		{
		case IPPROTO_TCP:
			tcph = (struct tcphdr *) ( datagram + sizeof( struct ip ) );
			tcph->th_sport = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC);
			tcph->th_dport = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST);

			iph->protocol = IPPROTO_TCP;
			len = iph->tot_len = sizeof( struct iphdr ) + sizeof( struct tcphdr );
			break;

		case IPPROTO_UDP:
			udph = (struct udphdr *) ( datagram + sizeof( struct ip ) );
			udph->uh_sport = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC);
			udph->uh_dport = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST);
			iph->protocol = IPPROTO_UDP;
			len = iph->tot_len = sizeof( struct iphdr ) + sizeof( struct udphdr );
			break;

		case IPPROTO_ICMP:
			iph->protocol = IPPROTO_ICMP;
			len = iph->tot_len = sizeof( struct iphdr );
			break;

		default:
			fprintf(stderr, "%s: default %d", __FUNCTION__, l4proto);
		}
	}else
	if( l3proto == AF_INET6 )
	{
		struct ip6_hdr *iphdr = (struct ip6_hdr *) datagram;

		iphdr->ip6_flow = htonl( ( 6 << 28 ) | ( 0 << 20 ) | 0);
		iphdr->ip6_hops = 255;

		memcpy(&iphdr->ip6_src, nfct_get_attr(ct, ATTR_ORIG_IPV6_SRC), sizeof( uint32_t )*4);
		memcpy(&iphdr->ip6_dst, nfct_get_attr(ct, ATTR_ORIG_IPV6_DST), sizeof( uint32_t )*4);

		len = sizeof( struct ip6_hdr );

		switch( l4proto )
		{
		case IPPROTO_TCP:
			tcph = (struct tcphdr *) ( datagram + IP6_HDRLEN );
			iphdr->ip6_plen = htons(TCP_HDRLEN);
			iphdr->ip6_nxt = IPPROTO_TCP;
			tcph->th_sport = ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC) );
			tcph->th_dport = ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST) );
			len = IP6_HDRLEN + TCP_HDRLEN;
			break;

		case IPPROTO_UDP:
			udph = (struct udphdr *) ( datagram + IP6_HDRLEN );
			udph->uh_sport = ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC) );
			udph->uh_dport = ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST) );
			iphdr->ip6_nxt = IPPROTO_UDP;
			len = IP6_HDRLEN + UDP_HDRLEN;
			break;

		case IPPROTO_ICMPV6:
			len = IP6_HDRLEN;
			break;

		default:
			fprintf(stderr, "%s:%d: default %d", __FUNCTION__, __LINE__, l4proto);
		}
	}

	g = g_nfctd->groups;

	for(; g != NULL; g = g->next )
	{
		if( bpf_filter(g->bpf->bf_insns,
		               (const u_char *) &datagram, len, len) > 0 )
		{
			entry = (struct nfctTable_entry *) nfctTable_get_by_groupId(g->id);
			increment_count_by_group_id(ct, entry);
		}
	}

	return MNL_CB_OK;
}

static void nfct_ev_netlink_cb(EV_P_ ev_io *w, int revents)
{
	nfct_catch(g_nfctd->netlink_handle);
}

static void timeout_cb_snmp(EV_P_ ev_timer *w, int revents)
{
}

static void io_snmp_cb(EV_P_ ev_timer *w, int revents)
{
}

static void snmp_prepare_cb(struct ev_loop *loop, ev_prepare *w, int revents)
{
	struct timeval ts;
	struct timeval ts2 = {
		1, 0
	};
	int block = 1;
	int snmp_numfds = 0;
	ev_tstamp ala = 0.0;
	/*
	   All permutations has been tested, this is the only one which seems to work
	 */
	snmp_select_info(&snmp_numfds, &g_nfctd->fdset, &ts2, &block);

	if( block == 0 )
	{

		if( ev_is_active(&g_nfctd->snmp_timer) )
			ev_timer_stop(loop, &g_nfctd->snmp_timer);

		memcpy(&ts, &ts2, sizeof( struct timeval ) );

		ts.tv_usec %= ONE_MILLION;
		ala = ts.tv_sec + ts.tv_usec * 1e-6;
		ala = MAX(ala, 1e-6);
		ala = MIN(ala, 15.0);

		ev_timer_init(&g_nfctd->snmp_timer, timeout_cb_snmp, ala, 0.);
		ev_timer_start(loop, &g_nfctd->snmp_timer);

	}

	for( int i = 0; i < g_nfctd->snmp_numfds; i++ )
		ev_io_stop(loop, g_nfctd->iow + i);

	if( snmp_numfds != g_nfctd->snmp_numfds )
	{
		free(g_nfctd->iow);
		g_nfctd->snmp_numfds = snmp_numfds;
		g_nfctd->iow = malloc(g_nfctd->snmp_numfds * sizeof( ev_io ) );
	}

	for( int i = 0; i < g_nfctd->snmp_numfds; i++ )
	{
		ev_io_init(g_nfctd->iow + i, io_snmp_cb, i, EV_READ);

		if( !FD_ISSET(i, &g_nfctd->fdset) )
			continue;

		ev_io_start(loop, g_nfctd->iow + i);
	}
}

// stop all watchers after blocking
static void snmp_check_cb(struct ev_loop *loop, ev_check *w, int revents)
{
	bool readable = false;

	for( int i = 0; i < g_nfctd->snmp_numfds; i++ )
	{
		if( !ev_is_active(g_nfctd->iow + i) )
			continue;

		readable |= ev_clear_pending(loop, g_nfctd->iow + i) & EV_READ;
		ev_io_stop(loop, g_nfctd->iow + i);
	}

	if( readable || ev_is_pending(&g_nfctd->snmp_timer) )
	{
		agent_check_and_process(0);

		if( ev_is_pending(&g_nfctd->snmp_timer) )
			snmp_timeout();
	}

	ev_timer_stop(loop, &g_nfctd->snmp_timer);

}

static void sigint_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
	ev_break(loop, EVBREAK_ALL);
}

struct nfctd_group *nfctd_group_new(void)
{
	struct nfctd_group *ng;
	ng = malloc(sizeof( struct nfctd_group ) );
	memset(ng, 0x0, sizeof( struct nfctd_group ) );
	return ng;
}

void init_snmp_groups(void)
{
	struct nfctd_group *g;
	struct nfctTable_entry *entry;

	for( g = g_nfctd->groups; g; g = g->next )
	{
		entry = nfctTable_createEntry(g->id);
		memcpy(entry->bpfFilter, g->filter, strlen(g->filter) );
		entry->bpfFilter_len = strlen(g->filter);
		memcpy(entry->label, g->label, strlen(g->label) );
		entry->label_len = strlen(g->label);
	}
}

void init_groups(void)
{
	struct lcfgx_tree_node *groups;
	struct lcfgx_tree_node *root, *n, *y;
	struct nfctd_group *grp;

	root = lcfgx_tree_new(g_nfctd->config);
	lcfgx_get_list(root, &groups, "groups");

	grp = nfctd_group_new();

	if( !g_nfctd->groups )
		g_nfctd->groups = grp;

	n = groups->value.elements;

	for(; n != NULL; n = n->next )
	{
		g_nfctd->group_count++;

		if( grp->label != NULL )
		{
			grp->next = nfctd_group_new();
			grp = grp->next;
		}

		lcfgx_get_string(n, &y, "label");
		grp->label = strndup(y->value.string.data, y->value.string.len);

		lcfgx_get_string(n, &y, "filter");
		grp->filter = strndup(y->value.string.data, y->value.string.len);

		lcfgx_get_string(n, &y, "id");
		grp->id = atoi(y->value.string.data);

		grp->bpf = malloc(sizeof( struct bpf_program ) );
		pcap_compile_nopcap(68, DLT_RAW, grp->bpf, grp->filter, 1, 0xffffffff);

		//fprintf(stderr, "group: id: %d label: '%s' filter: '%s'\n", grp->id, grp->label, grp->filter);
	}

	fprintf(stderr, "Loaded %d groups\n", g_nfctd->group_count);
}

void nfctd_prepare(void)
{
	// Get file descriptors
	g_nfctd->netlink_handle = nfct_open(CONNTRACK, NFCT_ALL_CT_GROUPS);

	if( g_nfctd->netlink_handle == NULL )
	{
		perror("nfct_open g_nfctd->netlink_handle");
		exit(EXIT_FAILURE);
	}

	g_nfctd->netlink_handle_fd = nfct_fd(g_nfctd->netlink_handle);
	fcntl(g_nfctd->netlink_handle_fd, F_SETFL, fcntl(g_nfctd->netlink_handle_fd, F_GETFL, 0) | O_NONBLOCK);

	if( nfct_callback_register2(g_nfctd->netlink_handle, NFCT_T_ALL, nfctsa_data_cb, NULL) < 0 )
	{
		perror("nfct_callback_register2 g_nfctd->netlink_handle");
		exit(EXIT_FAILURE);
	}
}

void sigsegv_backtrace_cb(int sig)
{
#define BACKTRACE_SIZE 256
	void *back[BACKTRACE_SIZE];
	size_t size;

	size = backtrace(back, BACKTRACE_SIZE);
	backtrace_symbols_fd(back, size, STDERR_FILENO);
	exit(-1);
}

void nfctd_new(const char *config_path)
{
	g_nfctd = malloc(sizeof( struct nfctd ) );
	memset(g_nfctd, 0x0, sizeof( struct nfctd ) );

	g_nfctd->loop = EV_DEFAULT;
	g_nfctd->config = lcfg_new(config_path);

	if( lcfg_parse(g_nfctd->config) != lcfg_status_ok )
	{
		fprintf(stderr, "lcfg error: %s\n", lcfg_error_get(g_nfctd->config) );
	}

	nfctd_prepare();
	init_groups();
	init_snmp_groups();

	ev_signal_init(&signal_watcher, sigint_cb, SIGINT | SIGTERM);
	ev_signal_start(g_nfctd->loop, &signal_watcher);

	ev_io_init(&g_nfctd->nf_callback_watcher, nfct_ev_netlink_cb,
	           g_nfctd->netlink_handle_fd, EV_READ);

	ev_timer_init(&g_nfctd->snmp_timer, 0, 1., 0.);
	ev_prepare_init(&g_nfctd->snmp_prepare, snmp_prepare_cb);
	ev_prepare_start(g_nfctd->loop, &g_nfctd->snmp_prepare);

	ev_check_init(&g_nfctd->snmp_check, snmp_check_cb);
	ev_check_start(g_nfctd->loop, &g_nfctd->snmp_check);

	ev_io_start(g_nfctd->loop, &g_nfctd->nf_callback_watcher);
	signal(SIGSEGV, sigsegv_backtrace_cb);
}

/**
 * Main loop
 */
int main(int argc, char *argv[])
{

	if( argc != 2 )
	{
		fprintf(stderr, "usage: %s FILE\n", argv[0]);
		return -1;
	}

	nfctd_new(argv[1]);

	snmp_enable_stderrlog();
	snmp_set_do_debugging(0);

	netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_ROLE, 1);

	/* initialize the agent library */
	init_agent("nfctd-agent");
	init_nfctd();

	init_snmp("nfctd");
	snmp_log(LOG_INFO, "nfctd is up and running PID=(%d).\n", getpid() );

	agent_check_and_process(0); // 0 non-blocking

	ev_run(g_nfctd->loop, 0);

	snmp_log(LOG_INFO, "exiting...\n");

	snmp_shutdown("nfctd");
	nfct_close(g_nfctd->netlink_handle);

	return 0;
}
