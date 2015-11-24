#include "summary.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>

#include "../lib/includes.h"
#include "../lib/logger.h"
#include "../lib/blacklist.h"

#include "state.h"
#include "probe_modules/probe_modules.h"
#include "output_modules/output_modules.h"

#define SI(w,x,y) printf("%s\t%s\t%i\n", w, x, y);
#define SD(w,x,y) printf("%s\t%s\t%f\n", w, x, y);
#define SU(w,x,y) printf("%s\t%s\t%u\n", w, x, y);
#define SLU(w,x,y) printf("%s\t%s\t%lu\n", w, x, (long unsigned int) y);
#define SS(w,x,y) printf("%s\t%s\t%s\n", w, x, y);


#define STRTIME_LEN 1024

void summary(void)
{
	FILE *summ_file = NULL;
	if (!(summ_file = fopen("zmap_summary.log", "w"))) {
                                log_fatal("csv", "could not open summary file");
                        }

	char send_start_time[STRTIME_LEN+1];
	assert(dstrftime(send_start_time, STRTIME_LEN, "%c", zsend.start));
	char send_end_time[STRTIME_LEN+1];
	assert(dstrftime(send_end_time, STRTIME_LEN, "%c", zsend.finish));
	char recv_start_time[STRTIME_LEN+1];
	assert(dstrftime(recv_start_time, STRTIME_LEN, "%c", zrecv.start));
	char recv_end_time[STRTIME_LEN+1];
	assert(dstrftime(recv_end_time, STRTIME_LEN, "%c", zrecv.finish));
	double hitrate = ((double) 100 * zrecv.success_unique)/((double)zsend.sent);
	
        fprintf(summ_file,"%s\t%s\t%u\n", "cnf", "target-port", zconf.target_port);
	fprintf(summ_file,"%s\t%s\t%u\n", "cnf", "source-port-range-begin", zconf.source_port_first);
	fprintf(summ_file,"%s\t%s\t%u\n", "cnf", "source-port-range-end", zconf.source_port_last);
	fprintf(summ_file,"%s\t%s\t%u\n", "cnf", "source-port-retransmit", zconf.source_port_retransmit);        
	fprintf(summ_file,"%s\t%s\t%s\n", "cnf", "source-addr-range-begin", zconf.source_ip_first);
	fprintf(summ_file,"%s\t%s\t%s\n", "cnf", "source-addr-range-end", zconf.source_ip_last);
        fprintf(summ_file,"%s\t%s\t%u\n","cnf", "maximum-targets", zconf.max_targets);
        fprintf(summ_file,"%s\t%s\t%u\n","cnf", "maximum-runtime", zconf.max_runtime);
        fprintf(summ_file,"%s\t%s\t%u\n","cnf", "maximum-results", zconf.max_results);
        fprintf(summ_file,"%s\t%s\t%lu\n", "cnf", "permutation-seed", (long unsigned int) zconf.seed);
        fprintf(summ_file,"%s\t%s\t%i\n","cnf", "cooldown-period", zconf.cooldown_secs);
        fprintf(summ_file,"%s\t%s\t%s\n","cnf", "send-interface", zconf.iface);
        fprintf(summ_file,"%s\t%s\t%i\n","cnf", "rate", zconf.rate);
        fprintf(summ_file,"%s\t%s\t%lu\n", "cnf", "bandwidth", (long unsigned int) zconf.bandwidth);
        fprintf(summ_file,"%s\t%s\t%u\n","cnf", "shard-num", (unsigned) zconf.shard_num);
        fprintf(summ_file,"%s\t%s\t%u\n","cnf", "num-shards", (unsigned) zconf.total_shards);
        fprintf(summ_file,"%s\t%s\t%u\n","cnf", "senders", (unsigned) zconf.senders);
        fprintf(summ_file,"%s\t%s\t%u\n","env", "nprocessors", (unsigned) sysconf(_SC_NPROCESSORS_ONLN));
        fprintf(summ_file,"%s\t%s\t%s\n","exc", "send-start-time", send_start_time);
        fprintf(summ_file,"%s\t%s\t%s\n","exc", "send-end-time", send_end_time);
        fprintf(summ_file,"%s\t%s\t%s\n","exc", "recv-start-time", recv_start_time);
        fprintf(summ_file,"%s\t%s\t%s\n","exc", "recv-end-time", recv_end_time);
        fprintf(summ_file,"%s\t%s\t%u\n","exc", "sent", zsend.sent);
        fprintf(summ_file,"%s\t%s\t%u\n","exc", "retransmitted", zsend.retransmitted);
        fprintf(summ_file,"%s\t%s\t%u\n","exc", "blacklisted", zsend.blacklisted);
        fprintf(summ_file,"%s\t%s\t%u\n","exc", "whitelisted", zsend.whitelisted);
        fprintf(summ_file,"%s\t%s\t%u\n","exc", "first-scanned", zsend.first_scanned);
        fprintf(summ_file,"%s\t%s\t%f\n","exc", "hit-rate", hitrate);
        fprintf(summ_file,"%s\t%s\t%u\n","exc", "success-total", zrecv.success_total);
        fprintf(summ_file,"%s\t%s\t%u\n","exc", "success-unique", zrecv.success_unique);
        // if there are application-level status messages, output
        if (zconf.fsconf.app_success_index >= 0) {
                fprintf(summ_file,"%s\t%s\t%u\n","exc", "app-success-total", zrecv.app_success_total);
                fprintf(summ_file,"%s\t%s\t%u\n","exc", "app-success-unique", zrecv.app_success_unique);
        }
        fprintf(summ_file,"%s\t%s\t%u\n","exc", "success-cooldown-total", zrecv.cooldown_total);
        fprintf(summ_file,"%s\t%s\t%u\n","exc", "success-cooldown-unique", zrecv.cooldown_unique);
        fprintf(summ_file,"%s\t%s\t%u\n","exc", "failure-total", zrecv.failure_total);
        fprintf(summ_file,"%s\t%s\t%u\n","exc", "tcp-badlen", zrecv.tcp_badlen);
        fprintf(summ_file,"%s\t%s\t%u\n","exc", "icmp-badlen", zrecv.icmp_badlen);
        fprintf(summ_file,"%s\t%s\t%u\n","exc", "sendto-failures", zsend.sendto_failures);
        fprintf(summ_file,"%s\t%s\t%u\n","adv", "permutation-gen", zconf.generator);
        fprintf(summ_file,"%s\t%s\t%s\n","exc", "scan-type", zconf.probe_module->name);

	fclose(summ_file);
/*
	SU("cnf", "target-port", zconf.target_port);
	SU("cnf", "source-port-range-begin", zconf.source_port_first);
	SU("cnf", "source-port-range-end", zconf.source_port_last);
	SU("cnf", "source-port-retransmit", zconf.source_port_retransmit);
	SS("cnf", "source-addr-range-begin", zconf.source_ip_first);
	SS("cnf", "source-addr-range-end", zconf.source_ip_last);
	SU("cnf", "maximum-targets", zconf.max_targets);
	SU("cnf", "maximum-runtime", zconf.max_runtime);
	SU("cnf", "maximum-results", zconf.max_results);
	SLU("cnf", "permutation-seed", zconf.seed);
	SI("cnf", "cooldown-period", zconf.cooldown_secs);
	SS("cnf", "send-interface", zconf.iface);
	SI("cnf", "rate", zconf.rate);
	SLU("cnf", "bandwidth", zconf.bandwidth);
	SU("cnf", "shard-num", (unsigned) zconf.shard_num);
	SU("cnf", "num-shards", (unsigned) zconf.total_shards);
	SU("cnf", "senders", (unsigned) zconf.senders);
	SU("env", "nprocessors", (unsigned) sysconf(_SC_NPROCESSORS_ONLN));
	SS("exc", "send-start-time", send_start_time);
	SS("exc", "send-end-time", send_end_time);
	SS("exc", "recv-start-time", recv_start_time);
	SS("exc", "recv-end-time", recv_end_time);
	SU("exc", "sent", zsend.sent);
	SU("exc", "retransmitted", zsend.retransmitted);
	SU("exc", "blacklisted", zsend.blacklisted);
	SU("exc", "whitelisted", zsend.whitelisted);
	SU("exc", "first-scanned", zsend.first_scanned);
	SD("exc", "hit-rate", hitrate);
	SU("exc", "success-total", zrecv.success_total);
	SU("exc", "success-unique", zrecv.success_unique);
	// if there are application-level status messages, output
	if (zconf.fsconf.app_success_index >= 0) {
		SU("exc", "app-success-total", zrecv.app_success_total);
		SU("exc", "app-success-unique", zrecv.app_success_unique);
	}
	SU("exc", "success-cooldown-total", zrecv.cooldown_total);
	SU("exc", "success-cooldown-unique", zrecv.cooldown_unique);
	SU("exc", "failure-total", zrecv.failure_total);
    	SU("exc", "tcp-badlen", zrecv.tcp_badlen);
    	SU("exc", "icmp-badlen", zrecv.icmp_badlen);
	SU("exc", "sendto-failures", zsend.sendto_failures);
	SU("adv", "permutation-gen", zconf.generator);
	SS("exc", "scan-type", zconf.probe_module->name);
*/
#ifdef JSON
    if (zconf.notes) {
	    SS("exc", "notes", zconf.notes);
    }
#endif
}

#ifdef JSON
#include <json.h>

void json_metadata(FILE *file)
{
	char send_start_time[STRTIME_LEN+1];
	assert(dstrftime(send_start_time, STRTIME_LEN, "%c", zsend.start));
	char send_end_time[STRTIME_LEN+1];
	assert(dstrftime(send_end_time, STRTIME_LEN, "%c", zsend.finish));
	char recv_start_time[STRTIME_LEN+1];
	assert(dstrftime(recv_start_time, STRTIME_LEN, "%c", zrecv.start));
	char recv_end_time[STRTIME_LEN+1];
	assert(dstrftime(recv_end_time, STRTIME_LEN, "%c", zrecv.finish));
	double hitrate = ((double) 100 * zrecv.success_unique)/((double)zsend.sent);

	json_object *obj = json_object_new_object();

	// scanner host name
	char hostname[1024];
	if (gethostname(hostname, 1023) < 0) {
		log_error("json-metadata", "unable to retrieve local hostname");
	} else {
		hostname[1023] = '\0';
		json_object_object_add(obj, "local-hostname",
                json_object_new_string(hostname));
		struct hostent* h = gethostbyname(hostname);
		if (h) {
			json_object_object_add(obj, "full-hostname",
                    json_object_new_string(h->h_name));
		} else {
			log_error("json-metadata", "unable to retrieve complete hostname");
		}
	}

	json_object_object_add(obj, "target-port",
			json_object_new_int(zconf.target_port));
	json_object_object_add(obj, "source-port-first",
			json_object_new_int(zconf.source_port_first));
	json_object_object_add(obj, "source_port-last",
			json_object_new_int(zconf.source_port_last));
	json_object_object_add(obj, "max-targets",
            json_object_new_int(zconf.max_targets));
	json_object_object_add(obj, "max-runtime",
            json_object_new_int(zconf.max_runtime));
	json_object_object_add(obj, "max-results",
            json_object_new_int(zconf.max_results));
	if (zconf.iface) {
		json_object_object_add(obj, "iface",
                json_object_new_string(zconf.iface));
	}
	json_object_object_add(obj, "rate",
            json_object_new_int(zconf.rate));
	json_object_object_add(obj, "bandwidth",
            json_object_new_int(zconf.bandwidth));
	json_object_object_add(obj, "cooldown-secs",
            json_object_new_int(zconf.cooldown_secs));
	json_object_object_add(obj, "senders",
            json_object_new_int(zconf.senders));
	json_object_object_add(obj, "use-seed",
            json_object_new_int(zconf.use_seed));
	json_object_object_add(obj, "seed",
            json_object_new_int64(zconf.seed));
	json_object_object_add(obj, "generator",
            json_object_new_int64(zconf.generator));
	json_object_object_add(obj, "hitrate",
            json_object_new_double(hitrate));
	json_object_object_add(obj, "shard-num",
            json_object_new_int(zconf.shard_num));
	json_object_object_add(obj, "total-shards",
            json_object_new_int(zconf.total_shards));

	json_object_object_add(obj, "syslog",
            json_object_new_int(zconf.syslog));
	json_object_object_add(obj, "filter-duplicates",
            json_object_new_int(zconf.filter_duplicates));
	json_object_object_add(obj, "filter-unsuccessful",
            json_object_new_int(zconf.filter_unsuccessful));

	json_object_object_add(obj, "pcap-recv",
            json_object_new_int(zrecv.pcap_recv));
	json_object_object_add(obj, "pcap-drop",
            json_object_new_int(zrecv.pcap_drop));
	json_object_object_add(obj, "pcap-ifdrop",
            json_object_new_int(zrecv.pcap_ifdrop));

	json_object_object_add(obj, "blacklisted",
            json_object_new_int64(zsend.blacklisted));
	json_object_object_add(obj, "whitelisted",
            json_object_new_int64(zsend.whitelisted));
	json_object_object_add(obj, "first-scanned",
            json_object_new_int64(zsend.first_scanned));
	json_object_object_add(obj, "send-to-failures",
            json_object_new_int64(zsend.sendto_failures));
	json_object_object_add(obj, "total-sent",
            json_object_new_int64(zsend.sent));

	json_object_object_add(obj, "success-total",
            json_object_new_int64(zrecv.success_total));
    json_object_object_add(obj, "tcp-badlen",
                           json_object_new_int64(zrecv.tcp_badlen));
    json_object_object_add(obj, "icmp-badlen",
                           json_object_new_int64(zrecv.icmp_badlen));
	json_object_object_add(obj, "success-unique",
            json_object_new_int64(zrecv.success_unique));
	if (zconf.fsconf.app_success_index >= 0) {
		json_object_object_add(obj, "app-success-total",
                json_object_new_int64(zrecv.app_success_total));
		json_object_object_add(obj, "app-success-unique",
                json_object_new_int64(zrecv.app_success_unique));
	}
	json_object_object_add(obj, "success-cooldown-total",
            json_object_new_int64(zrecv.cooldown_total));
	json_object_object_add(obj, "success-cooldown-unique",
            json_object_new_int64(zrecv.cooldown_unique));
	json_object_object_add(obj, "failure-total",
            json_object_new_int64(zrecv.failure_total));

	json_object_object_add(obj, "packet-streams",
			json_object_new_int(zconf.packet_streams));
	json_object_object_add(obj, "probe-module",
			json_object_new_string(((probe_module_t *)zconf.probe_module)->name));
	json_object_object_add(obj, "output-module",
			json_object_new_string(((output_module_t *)zconf.output_module)->name));

	json_object_object_add(obj, "send-start-time",
			json_object_new_string(send_start_time));
	json_object_object_add(obj, "send-end-time",
			json_object_new_string(send_end_time));
	json_object_object_add(obj, "recv-start-time",
			json_object_new_string(recv_start_time));
	json_object_object_add(obj, "recv-end-time",
			json_object_new_string(recv_end_time));

	if (zconf.output_filter_str) {
		json_object_object_add(obj, "output-filter",
				json_object_new_string(zconf.output_filter_str));
	}
	if (zconf.log_file) {
		json_object_object_add(obj, "log-file",
				json_object_new_string(zconf.log_file));
	}
	if (zconf.log_directory) {
		json_object_object_add(obj, "log-directory",
				json_object_new_string(zconf.log_directory));
	}

	if (zconf.destination_cidrs_len) {
		json_object *cli_dest_cidrs = json_object_new_array();
		for (int i=0; i < zconf.destination_cidrs_len; i++) {
			json_object_array_add(cli_dest_cidrs, json_object_new_string(zconf.destination_cidrs[i]));
		}
		json_object_object_add(obj, "cli-cidr-destinations",
				cli_dest_cidrs);
	}
	if (zconf.probe_args) {
		json_object_object_add(obj, "probe-args",
			json_object_new_string(zconf.probe_args));
	}
	if (zconf.output_args) {
		json_object_object_add(obj, "output-args",
			json_object_new_string(zconf.output_args));
	}

	if (zconf.gw_mac) {
		char mac_buf[ (MAC_ADDR_LEN * 2) + (MAC_ADDR_LEN - 1) + 1 ];
		memset(mac_buf, 0, sizeof(mac_buf));
		char *p = mac_buf;
		for(int i=0; i < MAC_ADDR_LEN; i++) {
			if (i == MAC_ADDR_LEN-1) {
				snprintf(p, 3, "%.2x", zconf.gw_mac[i]);
				p += 2;
			} else {
				snprintf(p, 4, "%.2x:", zconf.gw_mac[i]);
				p += 3;
			}
		}
		json_object_object_add(obj, "gateway-mac", json_object_new_string(mac_buf));
	}
	if (zconf.gw_ip) {
		struct in_addr addr;
		addr.s_addr = zconf.gw_ip;
		json_object_object_add(obj, "gateway-ip", json_object_new_string(inet_ntoa(addr)));
	}
	if (zconf.hw_mac) {
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
		json_object_object_add(obj, "source-mac", json_object_new_string(mac_buf));
	}

	json_object_object_add(obj, "source-ip-first",
			json_object_new_string(zconf.source_ip_first));
	json_object_object_add(obj, "source-ip-last",
			json_object_new_string(zconf.source_ip_last));
	if (zconf.output_filename) {
		json_object_object_add(obj, "output-filename",
				json_object_new_string(zconf.output_filename));
	}
	if (zconf.blacklist_filename) {
		json_object_object_add(obj,
			"blacklist-filename",
			json_object_new_string(zconf.blacklist_filename));
	}
	if (zconf.whitelist_filename) {
		json_object_object_add(obj,
			"whitelist-filename",
			json_object_new_string(zconf.whitelist_filename));
	}
	json_object_object_add(obj, "dryrun",
            json_object_new_int(zconf.dryrun));
	json_object_object_add(obj, "summary",
            json_object_new_int(zconf.summary));
	json_object_object_add(obj, "quiet",
            json_object_new_int(zconf.quiet));
	json_object_object_add(obj, "log_level",
            json_object_new_int(zconf.log_level));

    // parse out JSON metadata that was supplied on the command-line
    if (zconf.custom_metadata_str) {
        json_object *user = json_tokener_parse(zconf.custom_metadata_str);
        if (!user) {
            log_error("json-metadata", "unable to parse user metadata");
        } else {
	        json_object_object_add(obj, "user-metadata", user);
        }
    }

    if (zconf.notes) {
        json_object_object_add(obj, "notes",
                json_object_new_string(zconf.notes));
    }

	// add blacklisted and whitelisted CIDR blocks
	bl_cidr_node_t *b = get_blacklisted_cidrs();
	if (b) {
		json_object *blacklisted_cidrs = json_object_new_array();
		do {
			char cidr[50];
			struct in_addr addr;
			addr.s_addr = b->ip_address;
			sprintf(cidr, "%s/%i", inet_ntoa(addr), b->prefix_len);
			json_object_array_add(blacklisted_cidrs,
					json_object_new_string(cidr));
		} while (b && (b = b->next));
		json_object_object_add(obj, "blacklisted-networks", blacklisted_cidrs);
	}

	b = get_whitelisted_cidrs();
	if (b) {
		json_object *whitelisted_cidrs = json_object_new_array();
		do {
			char cidr[50];
			struct in_addr addr;
			addr.s_addr = b->ip_address;
			sprintf(cidr, "%s/%i", inet_ntoa(addr), b->prefix_len);
			json_object_array_add(whitelisted_cidrs,
					json_object_new_string(cidr));
		} while (b && (b = b->next));
		json_object_object_add(obj, "whitelisted-networks", whitelisted_cidrs);
	}

	fprintf(file, "%s\n", json_object_to_json_string(obj));
	json_object_put(obj);
}
#else
void json_metadata(FILE *file)
{
	(void) file;
	log_error("metadata", "JSON support not compiled in");
}
#endif
