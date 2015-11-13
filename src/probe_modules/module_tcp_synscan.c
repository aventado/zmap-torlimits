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

#include "../lib/logger.h"

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
  
	// Bano: By default lets use ack-non-retransmit port
	uint16_t the_source_port=htons(zconf.source_port_ack);

	// Bano: If it's a syn probe
	if(zconf.is_ack==0) 
	{
		// Bano: Set the syn-retransmit-port
		the_source_port=htons(zconf.source_port_retransmit);
	
		// Bano: If retransmissions are not enabled or we are not in
		// retransmission mode, set the syn-no-retransmit port
		if(!zconf.should_retransmit || zconf.mode_retransmit==0)
			the_source_port=htons(get_src_port(num_ports,
                        	                      probe_num, validation));
	}
	// If it's an ack packet, change flags and ack num. accordingly
	// (originally set in packet.c)
	else
	{
		// Bano: If retransmits are enabled and it's an ack probe and we are
        	// in retransmit mode, set the ack-retransmit-port
		if(zconf.should_retransmit && zconf.mode_retransmit==1)
                	the_source_port=htons(zconf.source_port_ack_retransmit);
		tcp_header->th_flags = 0;
		tcp_header->th_flags|=TH_ACK;
		tcp_header->th_ack=10;
	}		
		
	tcp_header->th_sport = the_source_port;
	tcp_header->th_seq = tcp_seq;
	tcp_header->th_sum = 0;
	tcp_header->th_sum = tcp_checksum(sizeof(struct tcphdr),
                                      ip_header->ip_src.s_addr, ip_header->ip_dst.s_addr, tcp_header);
    
	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *) ip_header);
   
	// Bano: Uncomment for debugging
	//fprintf(stdout,"^is_ack:%d\tsrc_port:%d\tshud_rexmit:%d\n",zconf.is_ack,ntohs(the_source_port),zconf.should_retransmit);	
 
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
    uint32_t src_ip_t = ip_hdr->ip_src.s_addr;
    uint32_t dst_ip_t = ip_hdr->ip_dst.s_addr;
    char *dipstr;   
 
    // Bano: Validating the packet by matching packet dst IP with the
    // corresponding global zmap scan source IP
    // NOTE: This will not work if multiple source IPs have been configured
    //if (strcmp(make_ip_str(dst_ip_t),zconf.source_ip_first)!=0) {
    dipstr = make_ip_str(dst_ip_t);
    if (strcmp(dipstr,zconf.source_ip_first)!=0) {
        //debug
        //log_warn("monitor","VALIDATE_SRCIP_FAIL. %s-->%s",make_ip_str(src_ip_t),make_ip_str(dst_ip_t));
	free(dipstr);
        return 0;
    }

    free(dipstr);    

    if (ip_hdr->ip_p == IPPROTO_TCP) {
	    //debug
	    //log_warn("monitor","VALIDATE_TCP_PKT");
        // buffer not large enough to contain expected tcp header
	    if ((4*ip_hdr->ip_hl + sizeof(struct tcphdr)) > len) {
            zrecv.tcp_badlen++;
            return 0;
		}
        
        struct tcphdr *tcp = (struct tcphdr*)((char *) ip_hdr + 4*ip_hdr->ip_hl);
        uint16_t sport = tcp->th_sport;
        uint16_t dport = tcp->th_dport;
        
        // Bano: We don't want this check because the packet could have been
        // injected by an intermediate device, not necessarily using the same
        // source port that we scanned
        
        // validate source port
        /*
         if (ntohs(sport) != zconf.target_port) {
            return 0;
        }
         */
        
        // Bano: Validating the packet by matching packet dst port with the
        // corresponding global zmap scan src port
        // NOTE: This will not work if multiple source ports have been configured
        if (ntohs(dport) != zconf.source_port_first && ntohs(dport) != zconf.source_port_ack && zconf.should_retransmit==0 || (zconf.should_retransmit==1 && ntohs(dport) != zconf.source_port_first && ntohs(dport) != zconf.source_port_ack && ntohs(dport) != zconf.source_port_retransmit && ntohs(dport) != zconf.source_port_ack_retransmit)) {
			//debug
			//log_warn("monitor","VALIDATE_TCP_FAIL. %s:%u-->%s:%u",make_ip_str(src_ip_t),ntohs(sport),make_ip_str(dst_ip_t),ntohs(dport));
			return 0;
        }
        
        // validate tcp acknowledgement number for responses to syn scan
        if (ntohs(dport) != zconf.source_port_ack && ntohs(dport) != zconf.source_port_ack_retransmit && htonl(tcp->th_ack) != htonl(validation[0])+1) {
            //log_warn("monitor","VALIDATE_TCP_ACK_FAIL. %s:%u-->%s:%u",make_ip_str(src_ip_t),ntohs(sport),make_ip_str(dst_ip_t),ntohs(dport));
            return 0;
        }
        
        //debug
        //log_warn("monitor","VALIDATE_TCP_PASS. %s:%u-->%s:%u",make_ip_str(src_ip_t),ntohs(sport),make_ip_str(dst_ip_t),ntohs(dport));
        
    }
    else if (ip_hdr->ip_p == IPPROTO_ICMP) {
        //debug
        //log_warn("monitor","VALIDATE_ICMP_PKT");
        
        //Bano: basic checks performed in recv.c in handle_packet() so no
        // need to repeat these here
        
        struct icmp *icmp = (struct icmp*) ((char *) ip_hdr + 4*ip_hdr->ip_hl);
        
        struct ip *ip_inner = (struct ip*) ((char *) icmp+8);

        uint32_t inner_src_ip = ip_inner->ip_src.s_addr;
        uint32_t inner_dst_ip = ip_inner->ip_dst.s_addr;

        
        // This is the packet we sent
        struct tcphdr *inner_tcp = (struct tcphdr*)((char *) ip_inner + 4*ip_inner->ip_hl);
        uint16_t inner_sport = inner_tcp->th_sport;
        uint16_t inner_dport = inner_tcp->th_dport;

        
        // Bano: We don't want this check because the packet could have been
        // injected by an intermediate device, not necessarily using the same
        // source port that we scanned
        
        // validate source port
        /*
         if (ntohs(inner_dport) != zconf.target_port) {
         return 0;
         }
         */
        
        // Bano: Validating the packet by matching packet dst port with the
        // corresponding global zmap scan src port
        // NOTE: This will not work if multiple source ports have been configured
        if (ntohs(inner_sport) != zconf.source_port_first && ntohs(inner_sport) != zconf.source_port_ack && zconf.should_retransmit==0 || (zconf.should_retransmit==1 && ntohs(inner_sport) != zconf.source_port_first && ntohs(inner_sport) != zconf.source_port_ack && ntohs(inner_sport) != zconf.source_port_retransmit && ntohs(inner_sport) != zconf.source_port_ack_retransmit)) {
			//debug
			//log_warn("monitor","VALIDATE_ICMP_TCP_SPORT_FAIL. %s:%u-->%s:%u",make_ip_str(inner_src_ip),ntohs(inner_sport),make_ip_str(inner_dst_ip),ntohs(inner_dport));
			return 0;
        }
        
        // validate tcp acknowledgement number for syn probes
        if ( (ntohs(inner_sport) == zconf.source_port_first || ntohs(inner_sport) == zconf.source_port_retransmit) && htonl(inner_tcp->th_seq) != htonl(validation[0]) ) {
            //debug
            //log_warn("monitor","VALIDATE_ICMP_TCP_ACK_FAIL. %s:%u:%u-->%s:%u:%u",make_ip_str(inner_src_ip),ntohs(inner_sport),htonl(inner_tcp->th_ack),make_ip_str(inner_dst_ip),ntohs(inner_dport),htonl(validation[0]));
            return 0;
        }

        //debug
        //log_warn("monitor","VALIDATE_ICMP_PASS: in_src-%s/in_dst%s:in_src_port%u-->src-%s",make_ip_str(inner_src_ip.s_addr),make_ip_str(inner_dst_ip.s_addr),ntohs(inner_sport), make_ip_str(src_ip_t));
        
    }
    else {
		return 0;
	}
	return 1;
}

void synscan_process_packet(const u_char *packet,
                            __attribute__((unused)) uint32_t len, fieldset_t *fs)
{
    struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];

    
    if (ip_hdr->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr*)((char *)ip_hdr
                                              + 4*ip_hdr->ip_hl);
        
        if (tcp->th_flags & TH_RST) { // RST packet
            fs_add_string(fs, "classification", (char*) "0", 0);
            fs_add_uint64(fs, "success", 1);
        } else { // SYNACK packet
            fs_add_string(fs, "classification", (char*) "1", 0);
            fs_add_uint64(fs, "success", 1);
        }	
        fs_add_uint64(fs, "sport", (uint64_t) ntohs(tcp->th_sport));
        fs_add_uint64(fs, "dport", (uint64_t) ntohs(tcp->th_dport));
       	
        //ICMP specific fields, adding null for TCP
        fs_add_null(fs, "inner_daddr");
        fs_add_null(fs, "icmp_type");
        fs_add_null(fs, "icmp_code");
        fs_add_uint64(fs, "seqnum", (uint64_t) ntohl(tcp->th_seq));
        fs_add_uint64(fs, "acknum", (uint64_t) ntohl(tcp->th_ack));
        fs_add_uint64(fs, "window", (uint64_t) ntohs(tcp->th_win));

	// Bano: Determine response corresponds to which type of probe
	// (syn-no-retransmit, syn-retransmit, ack-no-retransmit, ack-retransmit)
	// based on destination port 
	if (ntohs(tcp->th_dport) == zconf.source_port_ack)
                fs_add_string(fs, "is_retransmit", "A", 0);
	else if (ntohs(tcp->th_dport) == zconf.source_port_first)
                fs_add_string(fs, "is_retransmit", "S", 0);

	if(zconf.should_retransmit==1)
	{
		if (ntohs(tcp->th_dport) == zconf.source_port_ack_retransmit)
 	               fs_add_string(fs, "is_retransmit", "XA", 0);
        	else if (ntohs(tcp->th_dport) == zconf.source_port_retransmit)
                	fs_add_string(fs, "is_retransmit", "XS", 0);
	}	
       
    }
    else if (ip_hdr->ip_p == IPPROTO_ICMP) {
        
        struct icmp *icmp = (struct icmp*) ((char *) ip_hdr + 4*ip_hdr->ip_hl);
        
        struct ip *ip_inner = (struct ip*) ((char *) icmp+8);

	struct tcphdr *inner_tcp = (struct tcphdr*)((char *) ip_inner + 4*ip_inner->ip_hl);
	char *dipstr;
       
        fs_add_string(fs, "classification", (char*) "2", 0);
        fs_add_uint64(fs, "success", 1);
        fs_add_null(fs, "sport");
        fs_add_null(fs, "dport");
        // Get inner dest ip
        //struct in_addr inner_dst_ip = ip_inner->ip_dst;
	dipstr = make_ip_str(ip_inner->ip_dst.s_addr);
        fs_add_string(fs, "inner_daddr", dipstr, 1);
        fs_add_uint64(fs, "icmp_type", icmp->icmp_type);
        fs_add_uint64(fs, "icmp_code", icmp->icmp_code);
        //These are TCP specific fields and adding null for icmp
        fs_add_null(fs, "seqnum");
        fs_add_null(fs, "acknum");
        fs_add_null(fs, "window");

	if (ntohs(inner_tcp->th_sport) == zconf.source_port_ack)
                fs_add_string(fs, "is_retransmit", "A", 0);
	else if (zconf.source_port_first == zconf.source_port_retransmit)
                fs_add_string(fs, "is_retransmit", "X", 0);
	else if (ntohs(inner_tcp->th_sport) == zconf.source_port_retransmit)
                fs_add_string(fs, "is_retransmit", "R", 0);
        else
                fs_add_string(fs, "is_retransmit", "S", 0);

        //debug
        //log_warn("monitor","VALIDATE_ICMP_PROCESSED: %s",make_ip_str(ip_inner->ip_src.s_addr));
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
	{.name = "window", .type = "int", .desc = "TCP window"},
	{.name = "is_retransmit", .type = "string", .desc = "is is_retransmit packet"},
	{.name = "validation", .type = "int", .desc ="validation mark"}
};

probe_module_t module_tcp_synscan = {
	.name = "tcp_synscan",
	.packet_length = 54,
    .pcap_filter = "((dst port 41590 or dst port 41591 or dst port 41592 or dst port 41593) and (tcp[13] & 4 != 0 || tcp[13] == 18))",
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

