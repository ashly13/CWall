#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

// Struct for holding each rule
struct rule{
	unsigned long int src_ip;
	unsigned long int dest_ip;
	unsigned short int src_port;
	unsigned short int dest_port;
	char protocol;
};

// Hook Options structures
static struct nf_hook_ops input_filter;		// NF_INET_PRE_ROUTING - for incoming packets
static struct nf_hook_ops output_filter;	// NF_INET_POST_ROUTING - for outgoing packets

// Array of rules
static struct rule rules[100];
static int numRules = 1;

// Match the packet against the rule
int checkRule(struct rule *curr_rule, struct sk_buff *skb){

	if ( !skb ) {
		return NF_ACCEPT;
	}

	// The IP Header
	struct iphdr *ip_header;
	ip_header = (struct iphdr *)skb_network_header(skb);

	if ( !ip_header ) {
		return NF_ACCEPT;
	}

	struct udphdr *udp_header;
	struct tcphdr *tcp_header;

	// The rule matches the packet if and only if all non negative fields match
	
	// Match Source IP
	if ( curr_rule->src_ip != -1 && curr_rule->src_ip != (unsigned long int)ip_header->saddr ){
		return 0;
	}

	// Match Destination IP
	if ( curr_rule->dest_ip != -1 && curr_rule->dest_ip != (unsigned long int)ip_header->daddr ){
		return 0;
	}

	// Match the protocol
	if ( curr_rule->protocol != -1 && curr_rule->protocol != ip_header->protocol ){
		return 0;
	}

	// Get the protocol header and check the port numbers
	if ( ip_header->protocol == 6 ){	// TCP
		tcp_header = tcp_hdr(skb);
		
		// Match Source Port
		if ( curr_rule->src_port != -1 && curr_rule->src_port != (unsigned short int)tcp_header->source ){
			return 0;
		}

		// Match Destination Port
		if ( curr_rule->dest_port != -1 && curr_rule->dest_port != (unsigned short int)tcp_header->dest ){
			return 0;
		}

	}
	else if ( ip_header->protocol == 17 ){	// UDP
		udp_header = udp_hdr(skb);
		
		// Match Source Port
		if ( curr_rule->src_port != -1 && curr_rule->src_port != (unsigned short int)udp_header->source ){
			return 0;
		}

		// Match Destination Port
		if ( curr_rule->dest_port != -1 && curr_rule->dest_port != (unsigned short int)udp_header->dest ){
			return 0;
		}

	}

	return 1;

}

// Function that will perform filtering on incoming and outgoing packets
unsigned int hookfn(
		unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in, 
		const struct net_device *out,         
		int (*okfn)(struct sk_buff *)
		){
	// Loop through the array of rules and filter packets
	int i = 0;
	struct rule curr_rule;
	for (i = 0 ; i < numRules ; i++){
		curr_rule = rules[i];
		if ( checkRule(&curr_rule, skb) == 1 ){	// Check whether the rule applies here
			// Rule applies here, drop the packet
			return NF_DROP;
		}
	}
	return NF_ACCEPT;
}

// Load the rules as a linked list
void loadRules(void){
	// For now load rules manually
	// Rule to block HTTP traffic
	rules[0].src_ip = -1;
	rules[0].dest_ip = -1;	
	rules[0].src_port = -1;
	rules[0].dest_port = -1;	
	rules[0].protocol = 1;
}


int init_module(){
	
	// Load the rules
	loadRules();
	
	// Initialize Pre-Routing Filter
	input_filter.hook	= (nf_hookfn *)&hookfn;		// Hook Function
	input_filter.pf		= PF_INET;			// Protocol Family
	input_filter.hooknum	= NF_INET_PRE_ROUTING;		// Hook to be used
	input_filter.priority	= NF_IP_PRI_FIRST;		// Priority of our hook (makes multiple hooks possible)

	// Initialize Post-Routing Filter
	output_filter.hook	= (nf_hookfn *)&hookfn;		// Hook Function
	output_filter.pf	= PF_INET;			// Protocol Family
	output_filter.hooknum	= NF_INET_POST_ROUTING;		// Hook to be used
	output_filter.priority	= NF_IP_PRI_FIRST;		// Priority of our hook (makes multiple hooks possible)
	
	// Register our hooks
	nf_register_hook(&input_filter);
	nf_register_hook(&output_filter);

	return 0;

}

void cleanup_module(){
	// Unregister our hooks
	nf_unregister_hook(&input_filter);
	nf_unregister_hook(&output_filter);
}
