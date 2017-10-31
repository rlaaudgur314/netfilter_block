#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <libnet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

int host_block = 0;
char* target_host;

void usage()
{
	printf("syntax : netfilter_block <host name>\n");
	printf("sample : netfilter_block test.gilgil.net\n");
}

void block(int size, unsigned char* payload)
{
	struct libnet_ipv4_hdr* ip;
	struct libnet_tcp_hdr* tcp;
	unsigned char* data;
	char* host;

	ip = (struct libnet_ipv4_hdr*)payload;
	if(ip->ip_p == 0x06) // if TCP
	{
		tcp = (struct libnet_tcp_hdr*)(4 * ip->ip_hl + payload);
		if(size > 4 * ip->ip_p + 4 * tcp->th_off) // if data exist
		{
			data = (unsigned char*)tcp + 4 * tcp->th_off;
			
			if(memcmp(data, "GET ", 4) == 0 || memcmp(data, "POST ", 5) == 0 || memcmp(data, "HEAD ", 5) == 0 || memcmp(data, "PUT ", 4) == 0 || memcmp(data, "DELETE ", 7) == 0 || memcmp(data, "OPTIONS ", 8) == 0)
			{
				host = strstr((char *)data, "Host: ");

				if(host == NULL)
					return;
				host += strlen("Host: ");
				if(strncmp(host, target_host, strlen(target_host)) == 0)
				{
					host_block = 1;
					printf("target host blocked.\n");
				}
			}
		}
	}
}

static u_int32_t get_pkt_id(struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph)
		id = ntohl(ph->packet_id);
	
	ret = nfq_get_payload(tb, &data);
	if( ret >= 0)
		block(ret, data);

	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
	host_block = 0;
    u_int32_t id = get_pkt_id(nfa);
    //printf("entering callback\n");
    if(host_block)
    	return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}


int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		usage();
		return -1;
	}
	
	target_host = argv[1];

	struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            //printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
