#include <stdio.h>
#include <arpa/inet.h>
#include <check.h>
#include "../src/lldpd.h"

#define DUMP "ifdump.txt"

/* This is not a real test. It should dump into a file the list of interfaces */

static const char *
addr_string (struct sockaddr *sa) {
	static char buf[64];
	if (sa == NULL)
		return "<0000>";
	switch (sa->sa_family) {
	case AF_INET:
		return inet_ntop(AF_INET,
		    &((struct sockaddr_in *)sa)->sin_addr,
		    buf, sizeof(buf));
	case AF_INET6:
		return "<ipv6>";
	case AF_UNSPEC:
		return "<---->";
	case AF_PACKET:
		return "<pckt>";
	default:
		snprintf(buf, 64, "<%4d>", sa->sa_family);
	}
	return buf;
}

START_TEST (test_ifaddrs)
{
	struct ifaddrs *ifap, *ifa;
	FILE* dump;

	if (getifaddrs(&ifap) < 0) {
		fail("unable to get interface list");
		return;
	}
	dump = fopen(DUMP, "w+");
	if (dump == NULL) {
		fail("unable to open dump file " DUMP);
		return;
	}
	fprintf(dump,
	    "Name           Flags   Address         Netmask         Broadcast/Destination\n");
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		fprintf(dump, "%-15s%#.4x  ",
		    ifa->ifa_name, ifa->ifa_flags);
		fprintf(dump, "%-15s ",
		    addr_string(ifa->ifa_addr));
		fprintf(dump, "%-15s ",
		    addr_string(ifa->ifa_netmask));
		fprintf(dump, "%-15s\n",
		    addr_string(ifa->ifa_broadaddr));
	}
	fclose(dump);
}
END_TEST

Suite *
ifaddrs_suite(void)
{
	Suite *s = suite_create("getifaddrs");

	/* Single objects packing/unpacking */
	TCase *tc_core = tcase_create("getifaddrs");
	tcase_add_test(tc_core, test_ifaddrs);
	suite_add_tcase(s, tc_core);

	return s;
}

int
main()
{
	int number_failed;
	Suite *s = ifaddrs_suite ();
	SRunner *sr = srunner_create (s);
	srunner_run_all (sr, CK_ENV);
	number_failed = srunner_ntests_failed (sr);
	srunner_free (sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
