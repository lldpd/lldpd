#include <stdio.h>
#include <arpa/inet.h>
#include <check.h>
#include "common.h"

#define DUMP "ifdump.txt"

/* This is not a real test. It should dump into a file the list of interfaces */

static const char *
addr_string (struct sockaddr *sa) {
	static char buf[64];
	const char *res;
	if (sa == NULL)
		return "NULL";
	switch (sa->sa_family) {
	case AF_INET:
		res = inet_ntop(AF_INET,
		    &((struct sockaddr_in *)sa)->sin_addr,
		    buf, sizeof(buf));
		break;
	case AF_INET6:
		res = inet_ntop(AF_INET6,
		    &((struct sockaddr_in6 *)sa)->sin6_addr,
		    buf, sizeof(buf));
		break;
	case AF_UNSPEC:
		return "<--->";
	case AF_PACKET:
		return "<pkt>";
	default:
		snprintf(buf, 64, "<%4d>", sa->sa_family);
		return buf;
	}
	strcpy(buf, res);
	if (strlen(buf) > 26)
		memcpy(buf + 21, "[...]", strlen("[...]") + 1);
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
	    "Name           Flags    Address                    Netmask                    Broadcast/Destination\n");
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		fprintf(dump, "%-15s%#.5x  ",
		    ifa->ifa_name, ifa->ifa_flags);
		fprintf(dump, "%-26s ",
		    addr_string(ifa->ifa_addr));
		fprintf(dump, "%-26s ",
		    addr_string(ifa->ifa_netmask));
		fprintf(dump, "%-26s\n",
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
