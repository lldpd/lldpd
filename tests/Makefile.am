TESTS = check_marshal check_lldp check_cdp check_sonmp check_edp check_ifaddrs

if HAVE_CHECK

check_marshal_SOURCES = check_marshal.c \
	$(top_builddir)/src/marshal.h

check_lldp_SOURCES = check_lldp.c \
	$(top_builddir)/src/lldpd.h \
	common.h common.c

check_cdp_SOURCES = check_cdp.c \
	$(top_builddir)/src/lldpd.h \
	common.h common.c

check_sonmp_SOURCES = check_sonmp.c \
	$(top_builddir)/src/lldpd.h \
	common.h common.c

check_edp_SOURCES = check_edp.c \
	$(top_builddir)/src/lldpd.h \
	common.h common.c

check_ifaddrs_SOURCES = check_ifaddrs.c \
	$(top_builddir)/src/lldpd.h \
	$(top_builddir)/src/getifaddrs.c

AM_CFLAGS = @CHECK_CFLAGS@
LDADD = $(top_builddir)/src/liblldpd.la @CHECK_LIBS@

if USE_SNMP
TESTS += check_snmp
check_snmp_SOURCES = check_snmp.c \
	$(top_builddir)/src/lldpd.h \
	$(top_builddir)/src/agent.h

LDADD += @NETSNMP_LIBS@
endif

check_PROGRAMS = $(TESTS)

endif

MOSTLYCLEANFILES = lldp_send_*.pcap cdp_send_*.pcap sonmp_send_*.pcap edp_send_*.pcap \
	ifdump.txt
