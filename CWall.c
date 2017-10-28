#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

// Hook Options structures
static struct nf_hook_ops input_filter;		// NF_INET_PRE_ROUTING - for incoming packets
static struct nf_hook_ops output_filter;	// NF_INET_POST_ROUTING - for outgoing packets


// Function that will perform filtering on incoming packets
unsigned int input_hookfn(
		unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in, 
		const struct net_device *out,         
		int (*okfn)(struct sk_buff *)
		){
	return NF_DROP;	// Drop all packets (for now)
}

// Function that will perform filtering on outgoing packets
unsigned int output_hookfn(
		unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in, 
		const struct net_device *out,         
		int (*okfn)(struct sk_buff *)
		){
	return NF_DROP;	// Drop all packets (for now)
}


int init_module(){
	
	// Initialize Pre-Routing Filter
	input_filter.hook	= (nf_hookfn *)&input_hookfn;	// Hook Function
	input_filter.pf		= PF_INET;			// Protocol Family
	input_filter.hooknum	= NF_INET_PRE_ROUTING;		// Hook to be used
	input_filter.priority	= NF_IP_PRI_FIRST;		// Priority of our hook (makes multiple hooks possible)

	// Initialize Post-Routing Filter
	output_filter.hook	= (nf_hookfn *)&output_hookfn;	// Hook Function
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
