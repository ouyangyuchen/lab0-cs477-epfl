/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH 2
#endif

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		  h_proto == bpf_htons(ETH_P_8021AD));
}

/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (eth + 1 > data_end)
		return -1;

	nh->pos = eth + 1;
	*ethhdr = eth;

	__u16 proto = eth->h_proto;
	if (proto_is_vlan(proto)) {
		struct vlan_hdr *vh = nh->pos;

		#pragma unroll
		for (int i = 0; i < VLAN_MAX_DEPTH; i++) {
			if (&vh[i] + 1 > data_end)
				break;

			proto = vh[i].h_vlan_encapsulated_proto;
			if (!proto_is_vlan(proto))
				break;
			nh->pos = &vh[i] + 1;
		}
	}
	return proto; /* network-byte-order */
}

/* Assignment 2: Implement and use this */
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = nh->pos;

	if (ip6h + 1 > data_end)
		return -1;

	nh->pos = ip6h + 1;
	*ip6hdr = ip6h;

	return ip6h->nexthdr;
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
					void *data_end,
					struct iphdr **iph)
{
	struct iphdr *ipv4h = nh->pos;

	if (ipv4h + 1 > data_end)
		return -1;
	int hdrsize = ipv4h->ihl * 4;
	if ((char *)ipv4h + hdrsize > data_end)
		return -1;

	nh->pos = (char *)ipv4h + hdrsize;
	*iph = ipv4h;

	return ipv4h->protocol;
}

/* Assignment 3: Implement and use this */
static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *icmp6h = nh->pos;

	if (icmp6h + 1 > data_end)
		return -1;

	nh->pos   = icmp6h + 1;
	*icmp6hdr = icmp6h;

	return icmp6h->icmp6_type;
}

static __always_inline int parse_icmphdr(struct hdr_cursor *nh,
					 void *data_end,
					 struct icmphdr **icmphd)
{
	struct icmphdr *icmph = nh->pos;

	if (icmph + 1 > data_end)
		return -1;

	nh->pos  = icmph + 1;
	*icmphd = icmph;

	return icmph->type;
}

SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
	struct ipv6hdr *ip6h;
	struct icmp6hdr *icmp6h;
	struct iphdr *iph;
	struct icmphdr *icmph;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

        /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type == bpf_htons(ETH_P_IPV6)) {
		parse_ip6hdr(&nh, data_end, &ip6h);
		if (parse_icmp6hdr(&nh, data_end, &icmp6h) < 0)
			goto out;
		int seqno = bpf_ntohs(icmp6h->icmp6_sequence);
		if (seqno % 2 == 1)
			action = XDP_PASS;
		else
			action = XDP_DROP;
	}
	else if (nh_type == bpf_htons(ETH_P_IP)) {
		parse_iphdr(&nh, data_end, &iph);
		if (parse_icmphdr(&nh, data_end, &icmph) < 0)
			goto out;
		int seqno = bpf_ntohs(icmph->un.echo.sequence);
		if (seqno % 2 == 1)
			action = XDP_PASS;
		else
			action = XDP_DROP;
	}

out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
