/* Intercepts packet from given netfilter hook, and outputs to stdout:
   Useful for testing with rcv_ip. */
#include <sys/types.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter.h>

#include <libipq/libipq.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>

#define BUFSIZE 65536

static void die(struct ipq_handle *h);

static int
string_to_number(const char *s, int min, int max)
{
	int number;
	char *end;

	/* Handle hex, octal, etc. */
	number = (int)strtol(s, &end, 0);
	if (*end == '\0' && end != s) {
		/* we parsed a number, let's see if we want this */
		if (min <= number && number <= max)
			return number;
	}
	return -1;
}

static struct in_addr *
dotted_to_addr(const char *dotted)
{
	static struct in_addr addr;
	unsigned char *addrp;
	char *p, *q;
	int onebyte, i;
	char buf[20];

	/* copy dotted string, because we need to modify it */
	strncpy(buf, dotted, sizeof(buf) - 1);
	addrp = (unsigned char *) &(addr.s_addr);

	p = buf;
	for (i = 0; i < 3; i++) {
		if ((q = strchr(p, '.')) == NULL)
			return (struct in_addr *) NULL;
		else {
			*q = '\0';
			if ((onebyte = string_to_number(p, 0, 255)) == -1)
				return (struct in_addr *) NULL;
			else
				addrp[i] = (unsigned char) onebyte;
		}
		p = q + 1;
	}

	/* we've checked 3 bytes, now we check the last one */
	if ((onebyte = string_to_number(p, 0, 255)) == -1)
		return (struct in_addr *) NULL;
	else
		addrp[3] = (unsigned char) onebyte;

	return &addr;
}

int main(int argc, const char *argv[])
{
	int rval, user_verdict;
	unsigned int hookmask, count, wait, mangle, timeout, i;
	unsigned char packet[BUFSIZE];
	struct ipq_handle *h;
	u_int32_t srcip;

	if (argc < 5 || argc > 7) {
		fprintf(stderr,
			"Usage: %s hook-name verdict timeout count"
			"  [src=ipaddr] [wait] [`mangle']\n",
			argv[0]);
		return 1;
	}

	h = ipq_create_handle(0, PF_INET);
	if (!h)
		die(h);
	
	/* The queue does not need to be explicitly flushed now */
	
	/* Tell the queue to send packets up to size BUFSIZE */
	rval = ipq_set_mode(h, IPQ_COPY_PACKET, BUFSIZE);
	if (rval < 0)
		die(h);
		
	if (strcasecmp(argv[1], "LOCAL_IN") == 0)
		hookmask = 1 << NF_IP_LOCAL_IN;
	else if (strcasecmp(argv[1], "PRE_ROUTING") == 0)
		hookmask = 1 << NF_IP_PRE_ROUTING;
	else if (strcasecmp(argv[1], "FORWARD") == 0)
		hookmask = 1 << NF_IP_FORWARD;
	else if (strcasecmp(argv[1], "POST_ROUTING") == 0)
		hookmask = 1 << NF_IP_POST_ROUTING;
	else if (strcasecmp(argv[1], "LOCAL_OUT") == 0)
		hookmask = 1 << NF_IP_LOCAL_OUT;
	else {
		fprintf(stderr, "Unknown hook `%s'\n", argv[1]);
		return 1;
	}

	if (strcasecmp(argv[2], "ACCEPT") == 0)
		user_verdict = NF_ACCEPT;
	else if (strcasecmp(argv[2], "DROP") == 0)
		user_verdict = NF_DROP;
	else {
		fprintf(stderr, "Illegal verdict `%s'\n", argv[2]);
		return 1;
	}

	timeout = atoi(argv[3]);
	if (timeout < 1) {
		fprintf(stderr, "Illegal timeout `%s'\n", argv[3]);
		return 1;
	}

	count = atoi(argv[4]);
	if (count < 1) {
		fprintf(stderr, "Illegal count `%s'\n", argv[4]);
		return 1;
	}

	if (argc > 5 && strncmp(argv[5], "src=", 4) == 0) {
		const struct in_addr *addr;

		addr = dotted_to_addr(argv[5]+4);
		if (addr == NULL) {
			fprintf(stderr, "Illegal src `%s'\n", argv[5]);
			return 1;
		}
		argc--; argv++;
		srcip = addr->s_addr;
	} else
		srcip = 0;

	if (argc > 5) {
		wait = atoi(argv[5]);
		if (wait < 1) {
			fprintf(stderr, "Illegal wait `%s'\n", argv[5]);
			return 1;
		}
		argc--; argv++;
	} else
		wait = 0;

	if (argc > 5 && strcmp(argv[5], "mangle") == 0) {
		mangle = 1;
		argc--; argv++;
	} else
		mangle = 0;

	if (argc > 5) {
		fprintf(stderr, "Error in args: too many.\n");
		exit(1);
	}

	for (i = 0; i < count; ) {

		/* We'll die if we receive this. OK. */
		alarm(timeout);

	try_again:
		rval = ipq_read(h, packet, BUFSIZE, 0);
		if (rval < 0)
			die(h);

		switch (ipq_message_type(packet)) {
		
		case NLMSG_ERROR:
			fprintf(stderr, "Received error message %d\n",
				ipq_get_msgerr(packet));
			exit(1);

		case IPQM_PACKET: {
			unsigned char ehdr[16];
			ipq_packet_msg_t *m = ipq_get_packet(packet);
			unsigned char *payload = m->payload;
			
			if (rval == 0)
				goto try_again;

			/* Accept things we aren't interested in */
			if ((1 << m->hook) != hookmask
			    || (srcip
				&& ((struct iphdr *)payload)->saddr != srcip)){
				ipq_set_verdict(h, m->packet_id,
						NF_ACCEPT, m->data_len,
						payload);
				goto try_again;
			}

			if (getenv("VERBOSE")) {
				fprintf(stderr, "in=%s, out=%s, mk=%lu, "
					"len=%u, v=%s, hookmask=%u\n", 
				        m->indev_name[0] ? m->indev_name : "[none]",
				        m->outdev_name[0] ? m->outdev_name : "[none]",
				        m->mark,
				        m->data_len,
				        user_verdict == NF_ACCEPT ? "ACCEPT" 
				        : (user_verdict == NF_DROP ? "DROP" : "?"),
				        1 << m->hook);
			}
			
			/* Bogus ethernet header for rcv_ip */
			memset(&ehdr, 'E', sizeof(ehdr));
			write(STDOUT_FILENO, &ehdr, sizeof(ehdr));
			write(STDOUT_FILENO, payload, m->data_len);

			/* This usually wipes out alarm, but that's OK since
			   the rest shouldn't block. */
			if (wait)
				sleep(wait);

			if (mangle) {	/* Read in new packet from stdin. */
				
				/* Discard header. */
				read(STDIN_FILENO, payload, sizeof(ehdr));
				
				rval = read(STDIN_FILENO, payload, BUFSIZE - sizeof(*m));
				if (rval < 0) {
					perror("Reading new packet");
					exit(1);
				}
				
				m->data_len = rval;
				fprintf(stderr, "Mangling packet, new len=%d\n", rval);
			}
			
			/* Issue verdict and possibly modified packet*/
			rval = ipq_set_verdict(h, m->packet_id,
			                       user_verdict, m->data_len, payload);
			if (rval < 0)
					die(h);
			if (getenv("VERBOSE") && wait)
				fprintf(stderr, "intercept: reinjected.\n");
			i++;	
			break;
		}
			
		default:
			fprintf(stderr, "Unknown message!\n");
			exit(1);
		}
	}
	return 0;
}

static void die(struct ipq_handle *h)
{
	perror("intercept");
	ipq_perror("intercept");
	ipq_destroy_handle(h);
	exit(1);
}

