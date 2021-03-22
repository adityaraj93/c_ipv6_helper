#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

struct classification {
	struct classification		*class_next;
	struct classification		*class_last;
	const char			*class_name;
};

/* Add new classificaton */
static int add_class(struct classification *head, const char *name) {
	struct classification *cobj = calloc(1, sizeof(*cobj));
	if (NULL == cobj) {
		fprintf(stderr, "Failed to allocate class for %s\n",
				name);
		return -1;
	}
	cobj->class_name = name;
	if (NULL == head->class_next) {
		assert(head->class_last == NULL);
		head->class_next =
			head->class_last = cobj;
	}
	else {
		head->class_last->class_next = cobj;
		head->class_last = cobj;
	}
	return 0;
}

/* Print the classifications */
static void print_classes(struct classification *head, FILE *fp) {
	struct classification *cobj = head->class_next;

	printf("\n");
	while(NULL != cobj) {
		fprintf(fp, "%s ", cobj->class_name);
		cobj = cobj->class_next;
	}
	printf("\n");
}

#define IN6_IS_ADDR_UNICAST(a) ((((const uint32_t*)(a))[0] & htonl(0xe0000000)) == htonl(0x20000000))
#define IN6_IS_ADDR_PRIVATE(a) ((((const uint32_t*)(a))[0] & htonl(0xfe000000)) == htonl(0xfc000000))
#define IN6_IS_ADDR_TEREDO(a)  ((((const uint32_t*)(a))[0] & htonl(0xffffffff)) == htonl(0x20010000))
#define IN6_IS_ADDR_BENCHMARKING(a)  ((((const uint32_t*)(a))[0] & htonl(0xffffffff)) == htonl(0x20010002))
#define IN6_IS_ADDR_ORCHIDV2(a)	((((const uint32_t*)(a))[0] & htonl(0xfffffff0)) == htonl(0x20010020))
#define IN6_IS_ADDR_6TO4(a)	((((const uint32_t*)(a))[0] & htonl(0xffff0000)) == htonl(0x20020000))
#define IN6_IS_ADDR_DOC(a)	((((const uint32_t*)(a))[0] & htonl(0xffffffff)) == htonl(0x20010db8))
#define IN6_IS_ADDR_DISCARD(a)	((((const uint32_t*)(a))[0] & htonl(0xffffffff)) == htonl(0x01000000) &&\
				(((const uint32_t*)(a))[1]) == 0)
#define IN6_IS_ADDR_NAT64RSVD(a)	((((const uint32_t*)(a))[0] & htonl(0xffffffff)) == htonl(0x0064ff9b) &&\
					(((const uint32_t*)(a))[1]) == 0 &&\
					(((const uint32_t*)(a))[2]) == 0)
#define IN6_IS_ADDR_MC_SOLICITED(a)	((((const uint32_t*)(a))[0]) == htonl(0xff020000) &&\
					(((const uint32_t*)(a))[1]) == 0 &&\
					(((const uint32_t*)(a))[2]) == htonl(0x00000001) &&\
					(((const uint32_t*)(a))[3] & htonl(0xff000000)) == htonl(0xff000000))


static char* deconstruct_multicast(struct in6_addr *addr) {
	uint8_t flgs, scop, len = 0;
	const char *scop_str[0x10] = {
		[0x0] = "Reserved",
		[0x1] = "Interface-Local",
		[0x2] = "Link-Local",
		[0x3] = "Realm-Local",
		[0x4] = "Admin-Local",
		[0x5] = "Site-Local",
		[0x8] = "Organization-Local",
		[0xE] = "Global",
	};
	char *buf = calloc(1, 1024);

	assert(IN6_IS_ADDR_MULTICAST(addr));
	flgs = (addr->s6_addr[1] & 0xf0) >> 4;
	scop = addr->s6_addr[1] & 0xf;

	len += snprintf(buf + len, 1024, "\n\nMulticast Deconstruction:\n");
	len += snprintf(buf + len, 1024, "|   8    |  4 |  4 |                  112 bits                   |\n");
	len += snprintf(buf + len, 1024, "|11111111|flgs|scop|                  group ID                   |\n");
	len += snprintf(buf + len, 1024, "flgs: |0|R|P|T|\n");
#define FLGS_0(_f)	(((_f) & 0x8) >> 3)
#define FLGS_R(_f)	(((_f) & 0x4) >> 2)
#define	FLGS_P(_f)	(((_f) & 0x2) >> 1)
#define FLGS_T(_f)	(((_f) & 0x1) >> 0)
	len += snprintf(buf + len, 1024, "flgs: |%u|%u|%u|%u|\n", FLGS_0(flgs), FLGS_R(flgs), FLGS_P(flgs), FLGS_T(flgs));
	len += snprintf(buf + len, 1024, "scop: [%u] -> %s\n", scop, scop_str[scop] == NULL ? "Reserved" : scop_str[scop]);
	return buf;
}

/* Find which classes addr belongs to and enqueue them to the head */
static void classify(struct classification *head, struct in6_addr *addr) {
	if (IN6_IS_ADDR_UNSPECIFIED(addr))
		add_class(head, "UNSPECIFIED(::)");
	if (IN6_IS_ADDR_LOOPBACK(addr))
		add_class(head, "LOOPBACK(::1)");
	if (IN6_IS_ADDR_LINKLOCAL(addr))
		add_class(head, "LINKLOCAL(fe80::/10)");
	if (IN6_IS_ADDR_V4MAPPED(addr))
		add_class(head, "V4MAPPED(::ffff:0:0/96)");
	if (IN6_IS_ADDR_SITELOCAL(addr))
		add_class(head, "SITELOCAL(fec0::)");
	if (IN6_IS_ADDR_PRIVATE(addr))
		add_class(head, "PRIVATE(fc00::/7)");
	if (IN6_IS_ADDR_V4COMPAT(addr))
		add_class(head, "V4COMPAT(::0.0.0.0/96)");
	if (IN6_IS_ADDR_UNICAST(addr))
		add_class(head, "UNICAST(2000::/3)");
	if (IN6_IS_ADDR_TEREDO(addr))
		add_class(head, "TEREDO(2001:0000::/32)");
	if (IN6_IS_ADDR_BENCHMARKING(addr))
		add_class(head, "BENCHMARKING(2001:0002::/32)");
	if (IN6_IS_ADDR_ORCHIDV2(addr))
		add_class(head, "ORCHIDV2(2001:20::/28)");
	if (IN6_IS_ADDR_6TO4(addr))
		add_class(head, "6TO4(2002::/16)");
	if (IN6_IS_ADDR_DOC(addr))
		add_class(head, "DOCUMENTATION(2001:db8::/32)");
	if (IN6_IS_ADDR_DISCARD(addr))
		add_class(head, "DISCARD(100::/64)");
	if (IN6_IS_ADDR_NAT64RSVD(addr))
		add_class(head, "NAT64RESERVED(64:ff9b::/96)");
	if (IN6_IS_ADDR_MULTICAST(addr)) {
		add_class(head, "MULTICAST(ff00::/8)");
		if (IN6_IS_ADDR_MC_GLOBAL(addr))
			add_class(head, "MCGLOBAL(ffXe)");
		if (IN6_IS_ADDR_MC_LINKLOCAL(addr))
			add_class(head, "MCLINKLOCAL");
		if (IN6_IS_ADDR_MC_NODELOCAL(addr))
			add_class(head, "MCNODELOCAL");
		if (IN6_IS_ADDR_MC_ORGLOCAL(addr))
			add_class(head, "MCORGLOCAL");
		if (IN6_IS_ADDR_MC_SITELOCAL(addr))
			add_class(head, "MCSITELOCAL");
		if (IN6_IS_ADDR_MC_SOLICITED(addr))
			add_class(head, "MCSOLICITED(FF02:0:0:0:0:1:FF00::/104)");
		add_class(head, deconstruct_multicast(addr));
	}
}

static int parse_ip6(const char *addrstr, struct in6_addr *addr6) {
	if (1 != inet_pton(AF_INET6, addrstr, addr6))
		return -1;
	return 0;
}

static void usage(const char *progname) {
	printf("Usage:\n");
	printf("%s IPV6ADDRESS\n", progname);
}

int main(int argc, char *argv[]) {
	struct classification *head;
	struct in6_addr addr6;

	if (argc != 2) {
		fprintf(stderr, "Error: %s\n", strerror(EINVAL));
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (0 != parse_ip6(argv[1], &addr6)) {
		fprintf(stderr, "Failed to parse [%s]: %s\n", argv[1], strerror(EINVAL));
		exit(EXIT_FAILURE);
	}

	if (NULL == (head = calloc(1, sizeof(*head)))) {
		fprintf(stderr, "head allocation failed: %s\n", strerror(ENOMEM));
		exit(EXIT_FAILURE);
	}
	classify(head, &addr6);
	print_classes(head, stdout);
	return 0;
}
