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
	long int src_ip;
	long int dest_ip;
	int src_port;
	int dest_port;
	char protocol;
};

// Hook Options structures
static struct nf_hook_ops input_filter;		// NF_INET_PRE_ROUTING - for incoming packets
static struct nf_hook_ops output_filter;	// NF_INET_POST_ROUTING - for outgoing packets

// Array of rules
static struct rule rules[100];
static int numRules = 0;

// Match the packet against the rule
int checkRule(struct rule *curr_rule, struct sk_buff *skb){

	// The Network Layer Header
	struct iphdr *ip_header;

	// The Transport Layer Header
	struct udphdr *udp_header;
	struct tcphdr *tcp_header;

	if ( !skb ) {
		return NF_ACCEPT;
	}

	
	ip_header = (struct iphdr *)skb_network_header(skb);

	if ( !ip_header ) {
		return NF_ACCEPT;
	}

	// The rule matches the packet if and only if all non negative fields match
	
	//printk("Header - Source IP = %ld, Dest IP = %ld ; Rule - Source IP = %ld, Dest IP = %ld ", (long int)ntohl(ip_header->saddr), (long int)ntohl(ip_header->daddr), curr_rule->src_ip, curr_rule->dest_ip);

	// Match Source IP
	if ( curr_rule->src_ip != -1 && curr_rule->src_ip != (long int)ntohl(ip_header->saddr) ){
		return 0;
	}

	// Match Destination IP
	if ( curr_rule->dest_ip != -1 && curr_rule->dest_ip != (long int)ntohl(ip_header->daddr) ){
		return 0;
	}

	// Match the protocol
	if ( curr_rule->protocol != -1 && curr_rule->protocol != ip_header->protocol ){
		return 0;
	}

	// Get the protocol header and check the port numbers
	if ( ip_header->protocol == 6 ){	// TCP
		tcp_header = tcp_hdr(skb);
		//printk("Header - Src Port = %i, Dest Src = %i ; Rule - Src Port = %i, Dest Src = %i ", ntohs(tcp_header->source), ntohs(tcp_header->dest), curr_rule->src_port, curr_rule->dest_port);
	
		// Match Source Port
		if ( curr_rule->src_port == -1 || curr_rule->src_port == ntohs(tcp_header->source) ){
			// Match Destination Port
			if ( curr_rule->dest_port == -1 || curr_rule->dest_port == ntohs(tcp_header->dest) ){
				//printk("Rule Matches!!");
				return 1;
			}
		}

		return 0;

	}
	else if ( ip_header->protocol == 17 ){	// UDP
		udp_header = udp_hdr(skb);
	
		// Match Source Port
		if ( curr_rule->src_port == -1 || curr_rule->src_port == ntohs((unsigned short int)udp_header->source) ){
			// Match Destination Port
			if ( curr_rule->dest_port == -1 || curr_rule->dest_port == ntohs((unsigned short int)udp_header->dest) ){
				return 1;
			}
		}	

		return 0;

	}
	else if ( ip_header->protocol == 1 ){	// ICMP
	
		if ( curr_rule->src_port == -1 && curr_rule->dest_port == -1 ){
			return 1;
		}

	}
	return 0;
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

long int convertIP(unsigned char ip[]){
	long int result = (long int)ip[0]*256*256*256 + (long int)ip[1]*256*256 + (long int)ip[2]*256 + (long int)ip[3];
	printk("IP %d.%d.%d.%d = %ld", ip[0], ip[1], ip[2], ip[3], result);
	return result;
}

// Load the rules as a linked list
void loadRules(void){
	// For now load rules manually

	unsigned char ip[4];

	/*
	// Rule to block HTTP traffic
	numRules++;
	rules[numRules - 1].src_ip = -1;
	rules[numRules - 1].dest_ip = -1;	
	rules[numRules - 1].src_port = 80;
	rules[numRules - 1].dest_port = -1;	
	rules[numRules - 1].protocol = 6;
	*/
	/*
	// Rule to block all traffic to my IP
	numRules++;
	ip[0]=192;ip[1]=168;ip[2]=77;ip[3]=131;
	rules[numRules - 1].src_ip = convertIP(ip);
	rules[numRules - 1].dest_ip = -1;	
	rules[numRules - 1].src_port = -1;
	rules[numRules - 1].dest_port = -1;	
	rules[numRules - 1].protocol = -1;
	*/
	/*
	// Rule to block all ICMP traffic
	numRules++;
	rules[numRules - 1].src_ip = -1;
	rules[numRules - 1].dest_ip = -1;	
	rules[numRules - 1].src_port = -1;
	rules[numRules - 1].dest_port = -1;	
	rules[numRules - 1].protocol = 1;
	*/

	// Rule to block all UDP traffic
	numRules++;
	rules[numRules - 1].src_ip = -1;
	rules[numRules - 1].dest_ip = -1;	
	rules[numRules - 1].src_port = -1;
	rules[numRules - 1].dest_port = -1;	
	rules[numRules - 1].protocol = 17;

}


int init_module(){
	
	// Load the rules
	loadRules();
	
	// Initialize Pre-Routing Filter
	printk("Starting CWall");
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
	
	printk("Stopping CWall");
}
