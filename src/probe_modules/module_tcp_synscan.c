/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// probe module for performing TCP SYN scans

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "../../lib/includes.h"
#include "../fieldset.h"
#include "probe_modules.h"
#include "packet.h"

probe_module_t module_tcp_synscan;
static uint32_t num_ports;

int synscan_global_initialize(struct state_conf *state)
{
	num_ports = state->source_port_last - state->source_port_first + 1;
	return EXIT_SUCCESS;
}

int synscan_init_perthread(void* buf, macaddr_t *src,
		macaddr_t *gw, port_h_t dst_port,
		__attribute__((unused)) void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *) buf;
	make_eth_header(eth_header, src, gw);
	struct ip *ip_header = (struct ip*)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
	make_ip_header(ip_header, IPPROTO_TCP, len);
	struct tcphdr *tcp_header = (struct tcphdr*)(&ip_header[1]);
	make_tcp_header(tcp_header, dst_port);
	return EXIT_SUCCESS;
}

int synscan_make_packet(void *buf, ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
		uint32_t *validation, int probe_num, __attribute__((unused)) void *arg)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip *ip_header = (struct ip*)(&eth_header[1]);
	struct tcphdr *tcp_header = (struct tcphdr*)(&ip_header[1]);
	uint32_t tcp_seq = validation[0];

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;

	tcp_header->th_sport = htons(get_src_port(num_ports,
				probe_num, validation));
	tcp_header->th_seq = tcp_seq;
	tcp_header->th_sum = 0;
	tcp_header->th_sum = tcp_checksum(sizeof(struct tcphdr),
			ip_header->ip_src.s_addr, ip_header->ip_dst.s_addr, tcp_header);

	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *) ip_header);

	return EXIT_SUCCESS;
}

void synscan_print_packet(FILE *fp, void* packet)
{
	struct ether_header *ethh = (struct ether_header *) packet;
	struct ip *iph = (struct ip *) &ethh[1];
	struct tcphdr *tcph = (struct tcphdr *) &iph[1];
	fprintf(fp, "tcp { source: %u | dest: %u | seq: %u | checksum: %u }\n",
			ntohs(tcph->th_sport),
			ntohs(tcph->th_dport),
			ntohl(tcph->th_seq),
			ntohl(tcph->th_sum));
	fprintf_ip_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

int synscan_validate_packet(const struct ip *ip_hdr, uint32_t len,
		__attribute__((unused))uint32_t *src_ip,
		uint32_t *validation)
{
    
    if (ip_hdr->ip_p == IPPROTO_TCP) {
		if ((4*ip_hdr->ip_hl + sizeof(struct tcphdr)) > len) {
            // buffer not large enough to contain expected tcp header
            return 0;
        }
        struct tcphdr *tcp = (struct tcphdr*)((char *) ip_hdr + 4*ip_hdr->ip_hl);
        uint16_t sport = tcp->th_sport;
        uint16_t dport = tcp->th_dport;
        // validate source port
        if (ntohs(sport) != zconf.target_port) {
            return 0;
        }
        // validate tcp acknowledgement number
        if (htonl(tcp->th_ack) != htonl(validation[0])+1) {
            return 0;
        }
	}
    else if (ip_hdr->ip_p == IPPROTO_ICMP) {
        //Bano: Do we need some checks on length here?
        struct icmp *icmp = (struct icmp*) ((char *) ip_hdr + 4*ip_hdr->ip_hl);
        
        // Bano: Handling only ICMP error messages which can be received in response
        // to a TCP scan. We do not expect ICMP reply messages as these preclude an
        // ICMP request which we are not sending
        if ((icmp->icmp_type != ICMP_UNREACH) || (icmp->icmp_type != ICMP_SOURCEQUENCH) || (icmp->icmp_type != ICMP_REDIRECT) || (icmp->icmp_type != ICMP_TIMXCEED) || (icmp->icmp_type != ICMP_PARAMPROB)) {
            return 0;
        }
        
        // Note: Assuming here that ICMP header is 8 bytes long
        // which is the case for ICMP error messages
        struct ip *ip_inner = (struct ip*) &icmp[1];
        
        struct in_addr inner_src_ip = ip_inner->ip_src;
        struct in_addr inner_dst_ip = ip_inner->ip_dst;
        
        //Bano: Not sure what to do with this
        // Now we know the actual inner ip length, we should recheck the buffer
        //if (len < 4*ip_inner->ip_hl - sizeof(struct ip) + min_len) {
        //    return 0;
        
        // This is the packet we sent
        struct tcphdr *tcp = (struct tcphdr*)((char *) ip_inner + 4*ip_inner->ip_hl);
        uint16_t sport = tcp->th_sport;
        uint16_t dport = tcp->th_dport;
        
        // Bano: Validating the packet by matching inner packet src IP and ports with the
        // corresponding global zmap scan parameters
        // NOTE: This will not work if multiple source IP addresses or ports have been
        // configured
        if (strcmp(inet_ntoa(inner_src_ip),zconf.source_ip_first) != 0 || sport != zconf.source_port_first || dport != zconf.target_port) {
			return 0;
        }

    }
    else {
		return 0;
	}
    // validate destination port
    //if (!check_dst_port(sport, num_ports, validation)) {
    //    return 0;
    //}
	return 1;
}

void synscan_process_packet(const u_char *packet,
		__attribute__((unused)) uint32_t len, fieldset_t *fs)
{
	struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
    
    if (ip_hdr->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr*)((char *)ip_hdr
                        + 4*ip_hdr->ip_hl);

        fs_add_uint64(fs, "sport", (uint64_t) ntohs(tcp->th_sport));
        fs_add_uint64(fs, "dport", (uint64_t) ntohs(tcp->th_dport));
        fs_add_uint64(fs, "seqnum", (uint64_t) ntohl(tcp->th_seq));
        fs_add_uint64(fs, "acknum", (uint64_t) ntohl(tcp->th_ack));
        fs_add_uint64(fs, "window", (uint64_t) ntohs(tcp->th_win));

        if (tcp->th_flags & TH_RST) { // RST packet
            fs_add_string(fs, "classification", (char*) "TCP-rst", 0);
            fs_add_uint64(fs, "success", 0);
        } else { // SYNACK packet
            fs_add_string(fs, "classification", (char*) "TCP-synack", 0);
            fs_add_uint64(fs, "success", 1);
        }
    }
    else if (ip_hdr->ip_p == IPPROTO_ICMP) {

		struct icmp *icmp = (struct icmp *) ((char *) ip_hdr + ip_hdr->ip_hl * 4);
		struct ip *ip_inner = (struct ip *) &icmp[1];

		fs_add_string(fs, "classification", (char*) "icmp", 0);
		fs_add_uint64(fs, "success", 0);
        // Get inner dest ip
        struct in_addr inner_dst_ip = ip_inner->ip_dst;
        fs_add_string(fs, "inner_daddr", inet_ntoa(inner_dst_ip), 0);
		fs_add_null(fs, "sport");
		fs_add_null(fs, "dport");
		fs_add_uint64(fs, "icmp_type", icmp->icmp_type);
		fs_add_uint64(fs, "icmp_code", icmp->icmp_code);
        //These are TCP specific fields and adding null for icmp
        fs_add_null(fs, "seqnum");
        fs_add_null(fs, "acknum");
        fs_add_null(fs, "window");
	}
}

static fielddef_t fields[] = {
    {.name = "classification", .type="string", .desc = "packet classification"},
	{.name = "success", .type="int", .desc = "is response considered success"},
	{.name = "sport",  .type = "int", .desc = "TCP/ICMP source port"},
	{.name = "dport",  .type = "int", .desc = "TCP/ICMP destination port"},
    // Bano: Not logging source IP and src/dst ports as these being ZMap's are already known.
    // Also, ZMap replaces original saddr of icmp packet with the inner daddr and then have
    // an additional field icmp_responder for real daddr of the icmp packet. I let saddr and
    // daddr as they are in the packet, and add the field inner_daddr for the inner daddr
    {.name = "inner_daddr", .type = "string", .desc = "Dest IP of TCP packet within ICMP message"},
    //{.name = "icmp_responder", .type = "string", .desc = "Source IP of ICMP_UNREACH message"},
	{.name = "icmp_type", .type = "int", .desc = "icmp message type"},
	{.name = "icmp_code", .type = "int", .desc = "icmp message sub type code"},
	//{.name = "icmp_unreach_str", .type = "string", .desc = "for icmp_unreach responses, the string version of icmp_code (e.g. network-unreach)"},
	//{.name = "udp_pkt_size", .type="int", .desc = "UDP packet length"},
	//{.name = "data", .type="binary", .desc = "UDP payload"},
    // The following will have null values for ICMP
	{.name = "seqnum", .type = "int", .desc = "TCP sequence number"},
	{.name = "acknum", .type = "int", .desc = "TCP acknowledgement number"},
	{.name = "window", .type = "int", .desc = "TCP window"}
	
};

probe_module_t module_tcp_synscan = {
	.name = "tcp_synscan",
	.packet_length = 54,
	.pcap_filter = "icmp || (tcp && tcp[13] & 4 != 0 || tcp[13] == 18)",
	.pcap_snaplen = 96,
	.port_args = 1,
	.global_initialize = &synscan_global_initialize,
	.thread_initialize = &synscan_init_perthread,
	.make_packet = &synscan_make_packet,
	.print_packet = &synscan_print_packet,
	.process_packet = &synscan_process_packet,
	.validate_packet = &synscan_validate_packet,
	.close = NULL,
	.helptext = "Probe module that sends a TCP SYN packet to a specific "
		"port. Possible classifications are: synack, rst and icmp. A "
		"SYN-ACK packet is considered a success and a tcp reset or icmp packet "
		"is considered a failed response.",

	.fields = fields,
	.numfields = sizeof(fields)/sizeof(fields[0])
};

