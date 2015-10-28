/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "send.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "../lib/includes.h"
#include "../lib/logger.h"
#include "../lib/random.h"
#include "../lib/blacklist.h"
#include "../lib/lockfd.h"

//#define IP_RETRANSMIT_SIZE 1000000
#define IP_RETRANSMIT_SIZE 500

#include "aesrand.h"
#include "get_gateway.h"
#include "iterator.h"
#include "probe_modules/packet.h"
#include "probe_modules/probe_modules.h"
#include "shard.h"
#include "state.h"
#include "validate.h"

// OS specific functions called by send_run
static inline int send_packet(sock_t sock, void *buf, int len, uint32_t idx);
static inline int send_run_init(sock_t sock);


// Include the right implementations
#if defined(PFRING)
#include "send-pfring.h"
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__)
#include "send-bsd.h"
#else /* LINUX */
#include "send-linux.h"
#endif /* __APPLE__ || __FreeBSD__ || __NetBSD__ */

// The iterator over the cyclic group

// Lock for send run
static pthread_mutex_t send_mutex = PTHREAD_MUTEX_INITIALIZER;

// Source IP address for outgoing packets
static in_addr_t srcip_first;
static in_addr_t srcip_last;
static uint32_t srcip_offset;
static uint32_t num_src_addrs;

// Source ports for outgoing packets
static uint16_t num_src_ports;

// global sender initialize (not thread specific)
iterator_t* send_init(void)
{

	// generate a new primitive root and starting position
	iterator_t *it;
	it = iterator_init(zconf.senders, zconf.shard_num, zconf.total_shards);

	// process the dotted-notation addresses passed to ZMAP and determine
	// the source addresses from which we'll send packets;
	srcip_first = inet_addr(zconf.source_ip_first);
	if (srcip_first == INADDR_NONE) {
		log_fatal("send", "invalid begin source ip address: `%s'",
				zconf.source_ip_first);
	}
	srcip_last = inet_addr(zconf.source_ip_last);
	if (srcip_last == INADDR_NONE) {
		log_fatal("send", "invalid end source ip address: `%s'",
				zconf.source_ip_last);
	}
	log_debug("send", "srcip_first: %u", srcip_first);
	log_debug("send", "srcip_last: %u", srcip_last);
	if (srcip_first == srcip_last) {
		srcip_offset = 0;
		num_src_addrs = 1;
	} else {
		uint32_t ip_first = ntohl(srcip_first);
		uint32_t ip_last = ntohl(srcip_last);
		assert(ip_first && ip_last);
		assert(ip_last > ip_first);
		uint32_t offset = (uint32_t) (aesrand_getword(zconf.aes) & 0xFFFFFFFF);
		srcip_offset = offset % (srcip_last - srcip_first);
		num_src_addrs = ip_last - ip_first + 1;
	}

	// process the source port range that ZMap is allowed to use
	num_src_ports = zconf.source_port_last - zconf.source_port_first + 1;
	log_debug("send", "will send from %i address%s on %u source ports",
		  num_src_addrs, ((num_src_addrs ==1 ) ? "":"es"),
		  num_src_ports);

	// global initialization for send module
	assert(zconf.probe_module);
	if (zconf.probe_module->global_initialize) {
		zconf.probe_module->global_initialize(&zconf);
	}

	// concert specified bandwidth to packet rate
	if (zconf.bandwidth > 0) {
		int pkt_len = zconf.probe_module->packet_length;
		pkt_len *= 8;
		pkt_len += 8*24;	// 7 byte MAC preamble, 1 byte Start frame,
		                        // 4 byte CRC, 12 byte inter-frame gap
		if (pkt_len < 84*8) {
			pkt_len = 84*8;
		}
		if (zconf.bandwidth / pkt_len > 0xFFFFFFFF) {
			zconf.rate = 0;
		} else {
			zconf.rate = zconf.bandwidth / pkt_len;
			if (zconf.rate == 0) {
				log_warn("send", "bandwidth %lu bit/s is slower than 1 pkt/s, "
								"setting rate to 1 pkt/s", zconf.bandwidth);
				zconf.rate = 1;
			}
		}
		log_debug("send", "using bandwidth %lu bits/s, rate set to %d pkt/s",
						zconf.bandwidth, zconf.rate);
	}

	// Get the source hardware address, and give it to the probe
	// module
    if (!zconf.hw_mac_set) {
	    if (get_iface_hw_addr(zconf.iface, zconf.hw_mac)) {
	    	log_fatal("send", "could not retrieve hardware address for "
	    		  "interface: %s", zconf.iface);
	    	return NULL;
	    }
        log_debug("send", "no source MAC provided. "
                "automatically detected %02x:%02x:%02x:%02x:%02x:%02x as hw "
                "interface for %s",
                zconf.hw_mac[0], zconf.hw_mac[1], zconf.hw_mac[2],
                zconf.hw_mac[3], zconf.hw_mac[4], zconf.hw_mac[5],
                zconf.iface);
    }
	log_debug("send", "source MAC address %02x:%02x:%02x:%02x:%02x:%02x",
           zconf.hw_mac[0], zconf.hw_mac[1], zconf.hw_mac[2],
           zconf.hw_mac[3], zconf.hw_mac[4], zconf.hw_mac[5]);

	if (zconf.dryrun) {
		log_info("send", "dryrun mode -- won't actually send packets");
	}

	// initialize random validation key
	validate_init();

	zsend.start = now();
	return it;
}

static inline ipaddr_n_t get_src_ip(ipaddr_n_t dst, int local_offset)
{
	if (srcip_first == srcip_last) {
		return srcip_first;
	}
	return htonl(((ntohl(dst) + srcip_offset + local_offset)
			% num_src_addrs)) + srcip_first;
}

// one sender thread
int send_run(sock_t st, shard_t *s)
{
	log_trace("send", "send thread started");
	pthread_mutex_lock(&send_mutex);
	// Allocate a buffer to hold the outgoing packet
	char buf[MAX_PACKET_SIZE];
	// //Bano: Allocate a buffer to hold the outgoing ACK packet
        char buf_ack[MAX_PACKET_SIZE];
	memset(buf, 0, MAX_PACKET_SIZE);
	memset(buf_ack, 0, MAX_PACKET_SIZE);

	// OS specific per-thread init
	if (send_run_init(st)) {
		return -1;
	}

	// MAC address length in characters
	char mac_buf[(ETHER_ADDR_LEN * 2) + (ETHER_ADDR_LEN - 1) + 1];
	char *p = mac_buf;
	for(int i=0; i < ETHER_ADDR_LEN; i++) {
		if (i == ETHER_ADDR_LEN-1) {
			snprintf(p, 3, "%.2x", zconf.hw_mac[i]);
			p += 2;
		} else {
			snprintf(p, 4, "%.2x:", zconf.hw_mac[i]);
			p += 3;
		}
	}
	log_debug("send", "source MAC address %s",
			mac_buf);
	void *probe_data;
	if (zconf.probe_module->thread_initialize) {
		zconf.probe_module->thread_initialize(buf, zconf.hw_mac, zconf.gw_mac,
					      zconf.target_port, &probe_data);
	        //Bano: For ack packet
		zconf.probe_module->thread_initialize(buf_ack, zconf.hw_mac, zconf.gw_mac,
                                              zconf.target_port, &probe_data);
	}
	pthread_mutex_unlock(&send_mutex);

	// adaptive timing to hit target rate
	uint32_t count = 0;
	uint32_t last_count = count;
	double last_time = now();
	uint32_t delay = 0;
	int interval = 0;
	uint32_t max_targets = s->state.max_targets;
	volatile int vi;
	if (zconf.rate > 0) {
		// estimate initial rate
		delay = 10000;
		for (vi = delay; vi--; )
			;
		delay *= 1 / (now() - last_time) / (zconf.rate / zconf.senders);
		interval = (zconf.rate / zconf.senders) / 20;
		last_time = now();
	}

	//Bano: packet retransmission stuff
	// A queue of size K(=IP_RETRANSMIT_SIZE). If zconf.should_retransmit
	// is 1, then the send function operates in two modes, send and
	// retransmit. After sending scan packets to K IP addresses, the 
	// program switches to retransmit mode and resends scan packets to
	// the same K IP addresses and so forth.
	uint32_t ips_to_retransmit[IP_RETRANSMIT_SIZE];
	// keeps track of how many packets have been sent in the Send mode
        int count_retransmit=0;
	// iterates through the queue ips_to_retransmit
        int idx_ips_to_retransmit=0;
	// this operates in three modes: 0 means regular mode, that is 
	// K Send packets then K retransmits and so forth. 1 means that
	// the last n%K packets have been sent and 2 means that the last
	// n%K packets have been retransmitted
        int retransmit_switch=0;
	// How many times to iterate through ips_to_retransmit. Effectively, 
	// this translates to how many probes to send per IP address
	int n_probes=1;
	// keeps track of which iteration of retransmissions is this
	int idx_probes=0;
	// indicates if all sends and retransmissions have completed and 
	// it's time to stop
	int all_done=0;
	
	uint32_t curr = shard_get_cur_ip(s);
	ips_to_retransmit[count_retransmit++]=curr;

	int attempts = zconf.num_retries + 1;
	uint32_t idx = 0;
	
	while (1) {
		// adaptive timing delay
		if (delay > 0) {
			count++;
			for (vi = delay; vi--; )
				;
			if (!interval || (count % interval == 0)) {
				double t = now();
				delay *= (double)(count - last_count)
					/ (t - last_time) / (zconf.rate / zconf.senders);
				if (delay < 1)
					delay = 1;
				last_count = count;
				last_time = t;
			}
		}
		if (zrecv.complete) {
			s->cb(s->id, s->arg);
			break;
		}

		//if retransmits are enabled
		// Bano: It seems that this one is a subset of the one below that just checks
		// if retransmit_switch is 2
		if(zconf.should_retransmit && zconf.is_ack==1 && (s->state.sent >= max_targets && all_done==1)) {
			s->cb(s->id, s->arg);
			log_trace("send", "send thread %hhu finished (max targets of %u reached)", s->id, max_targets);
			break;
		}
		
		//if retransmits are NOT enabled
		else if (!zconf.should_retransmit && zconf.is_ack==1 && s->state.sent >= max_targets) {
                        s->cb(s->id, s->arg);
                        log_trace("send", "send thread %hhu finished (max targets of %u reached)", s->id, max_targets);
                        break;
                }

		if (zconf.max_runtime && zconf.max_runtime <= now() - zsend.start) {
			s->cb(s->id, s->arg);
			break;
		}
		// if retransmits are enabled
		if (zconf.should_retransmit && zconf.is_ack==1 && all_done==1) {
			s->cb(s->id, s->arg);
			log_trace("send", "send thread %hhu finished, shard depleted", s->id);
			break;
		}
		//if retransmits are NOT enabled
		else if (!zconf.should_retransmit && zconf.is_ack==1 && curr==0) {
                        s->cb(s->id, s->arg);
                        log_trace("send", "send thread %hhu finished, shard depleted", s->id);
                        break;
                }
		//s->state.sent++;
		for (int i=0; i < zconf.packet_streams; i++) {
			uint32_t src_ip = get_src_ip(curr, i);

		  	uint32_t validation[VALIDATE_BYTES/sizeof(uint32_t)];
			validate_gen(src_ip, curr, (uint8_t *)validation);
			if(zconf.is_ack==0)
				zconf.probe_module->make_packet(buf, src_ip, curr, validation, i, probe_data);
			// Bano: For ack packet
			else if(zconf.is_ack==1)
				zconf.probe_module->make_packet(buf_ack, src_ip, curr, validation, i, probe_data);
	
			/*
			// Bano: If it is repeat of a probe,
                        // inject delay of 10 sec
                        if(i!=0)
                        	{
				clock_t endwait;
        			// wait for 10 second
        			endwait=clock()+10*CLOCKS_PER_SEC;
        			while (clock()<endwait);
				}
			*/
	
			if (zconf.dryrun) 	{
				lock_file(stdout);
				if(zconf.is_ack==0)
					zconf.probe_module->print_packet(stdout, buf);
				//Bano: display ack packet
				else
					zconf.probe_module->print_packet(stdout, buf_ack);
				unlock_file(stdout);
			} else {
				int length = zconf.probe_module->packet_length;
				void *contents = buf + zconf.send_ip_pkts*sizeof(struct ether_header);
				void *contents_ack = buf_ack + zconf.send_ip_pkts*sizeof(struct ether_header);
				for (int i = 0; i < attempts; ++i) {

					//Bano: uncomment for debugging  
					/*                 
                                        lock_file(stdout);
                                        if(zconf.mode_retransmit==0)
                                                fprintf(stdout,"^S\t-\t%f\t%s\n",now(),make_ip_str(curr));
                                        //fprintf(stdout,"^\t%f\t%lu\n",now(),curr);
                                        else
                                                fprintf(stdout,"^R\t%d\t%f\t%s\n",idx_probes,now(),make_ip_str(curr));
                                        unlock_file(stdout);
					*/
                                        //****************

					int rc=0;
					//Bano: Send ack packet
					if(zconf.is_ack==1)
					{
						rc = send_packet(st, contents_ack, length, idx);
						zconf.is_ack=0;
					}
					//Bano: Else send syn packet
					else
					{
						rc = send_packet(st, contents, length, idx);
						zconf.is_ack=1;
					}
                                        if (rc < 0) {
                                                struct in_addr addr;
                                                addr.s_addr = curr;
                                                log_warn("monitor", "send_packet failed for %s. %s",
                                                                  inet_ntoa(addr), strerror(errno));
                                                s->state.failures++;
                                        } else {
                                                break;
                                        }
				}
				idx++;
				idx &= 0xFF;
			}
		}

		// Packet retransmission code begins
		// if K IP addresses have been scanned OR the last n%K IP addreses
		// have been scanned (indicated by retransmit_switch=1)
		if(zconf.should_retransmit && (count_retransmit==IP_RETRANSMIT_SIZE || retransmit_switch==1))
			{
			if(zconf.is_ack==1)
			{
			//printf("*********RETRANSMITING************\n");
			// now retransmission mode
			zconf.mode_retransmit=1;	
		
			// Bano: If n%K packets are being retransmitted (indicated by retransmit_switch),
			// then prior to that waste some time crafting n-n%K dummy packets, before actually
			// transmitting the n%k packets. The idea is that we want to have consistent delay
			// between an original probe and the corresponding repeat probe 
			if(retransmit_switch==1 && idx_ips_to_retransmit==0)
				{
				int max_idx=IP_RETRANSMIT_SIZE-(max_targets%IP_RETRANSMIT_SIZE);
				for(int x=0; x<max_idx; x++)
                                                {
                                                // adaptive timing delay
                                                if (delay > 0) {
                                                        count++;
                                                        for (vi = delay; vi--; )
                                                                ;
                                                        if (!interval || (count % interval == 0)) {
                                                                double t = now();
                                                                delay *= (double)(count - last_count)
                                                                        / (t - last_time) / (zconf.rate / zconf.senders);
                                                                if (delay < 1)
                                                                        delay = 1;
                                                                last_count = count;
                                                                last_time = t;
                                                        }
                                                }
                                                int i=0;
                                                // integer representation of local loopback 127.0.0.1 
                                                curr=16777343;
                                                uint32_t src_ip = get_src_ip(curr, i);
                                                uint32_t validation[VALIDATE_BYTES/sizeof(uint32_t)];
                                                validate_gen(src_ip, curr, (uint8_t *)validation);
						if(zconf.is_ack==0)
                                                	zconf.probe_module->make_packet(buf, src_ip, curr, validation, i, probe_data);
						//Bano: Also make a dummy ack packet
						else
							zconf.probe_module->make_packet(buf_ack, src_ip, curr, validation, i, probe_data);
						//Bano: uncomment for debugging
						/*	
						lock_file(stdout);
						fprintf(stdout,"^RX\t%d\t%f\t%s\n",idx_probes,now(),make_ip_str(curr));	
						unlock_file(stdout);
						*/
						//************
                                                } 
				}

			curr=ips_to_retransmit[idx_ips_to_retransmit++];
			s->state.retransmitted++;

			// Bano: If the num. of packets retransmitted (idx_ips_to_retransmit) equals
			// the number of original probes in the send orbit
			// Note: I use count_retransmit instead of IP_RETRANSMIT_SIZE because if
			// n%K!=0, then in the last orbit idx_ips_to_retransmit will be less than
			// IP_RETRANSMIT_SIZE 
			if(idx_ips_to_retransmit==count_retransmit)
				{
				 // Bano: Increment the number of retransmission iterations done
				 idx_probes++;

				// Bano: If the last n%K packets have been retransmitted for
				// the desired number of retransmit iterations, then stop  
				if(retransmit_switch == 1 && idx_probes == n_probes)
					{
                                        //retransmit_switch=2;
					all_done=1;	
					}
				if(retransmit_switch == 1)
					curr=16777343;
                                        
				idx_ips_to_retransmit=0;

				if(idx_probes == n_probes)
					count_retransmit=0;
	
				//lock_file(stdout);
                                //fprintf(stdout,"^retransmission batch complete at %f with %d sent\n",now(),s->state.sent);
                                //unlock_file(stdout);
				}
			}
			}
		else
			{
			if(zconf.is_ack==1) 
			{
			// Send mode
			zconf.mode_retransmit=0;

			// Bano: Reset restransmit iterations to 0
			idx_probes=0;

			s->state.sent++;

			curr = shard_get_next_ip(s);

			
			//lock_file(stdout);
			//fprintf(stdout,"^Y\t%f\t%s\n",now(),make_ip_str(curr));
			//unlock_file(stdout);
			

			// Bano: Add the next IP address to scan to the retransmission queue
			if(zconf.should_retransmit)
				ips_to_retransmit[count_retransmit++]=curr;

			// Bano: If retransmissions are on, and send finish conditions have been reached,
			// that is, the entire v4 has been scanned (curr=0), OR maximum targets have
			// been scanned
			if(zconf.should_retransmit && (curr==0 || s->state.sent >= max_targets))
				{
				// Bano: If the packets sent in this orbit correspond to the last n%K
				// IP addresses, in which case, we just send a dummy packet to the local
				// loopback and then switch to retransmission of the last n%K packets
				if(max_targets>IP_RETRANSMIT_SIZE && max_targets%IP_RETRANSMIT_SIZE!=0)
					{
					//printf("*********RETRANSMITING************\n");
					//curr=ips_to_retransmit[idx_ips_to_retransmit++];
					// local loopback 
					curr=16777343;
					retransmit_switch=1;
					}
				// Bano: If we are coming here after retransmission of a regular orbit
				// and find there is no more to send
				else
					{
					// retransmit_switch=2;
					all_done=1;

					//Bano: uncomment for debugging
					/*  
					lock_file(stdout);
                                        fprintf(stdout,"^last sent check complete at %f and sent %d\n",now(),s->state.sent);
                                        unlock_file(stdout);
					*/
					//*******************
					}
				}
			}
			}
	}
	if (zconf.dryrun) {
		lock_file(stdout);
		fflush(stdout);
		unlock_file(stdout);
	}
	log_debug("send", "thread %hu finished", s->id);
	return EXIT_SUCCESS;
}
