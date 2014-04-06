AM_CFLAGS = -I $(top_srcdir)/include

if HAVE_CHECK

TESTS = check_marshal check_pattern check_lldp check_cdp check_sonmp check_edp check_fixedpoint
AM_CFLAGS += @CHECK_CFLAGS@
LDADD = $(top_builddir)/src/daemon/liblldpd.la @CHECK_LIBS@ @LIBEVENT_LDFLAGS@

check_marshal_SOURCES = check_marshal.c \
	$(top_srcdir)/src/marshal.h

check_pattern_SOURCES = check_pattern.c \
	$(top_srcdir)/src/daemon/lldpd.h

check_lldp_SOURCES = check_lldp.c \
	$(top_srcdir)/src/daemon/lldpd.h \
	common.h common.c

check_cdp_SOURCES = check_cdp.c \
	$(top_srcdir)/src/daemon/lldpd.h \
	common.h common.c

check_sonmp_SOURCES = check_sonmp.c \
	$(top_srcdir)/src/daemon/lldpd.h \
	common.h common.c

check_edp_SOURCES = check_edp.c \
	$(top_srcdir)/src/daemon/lldpd.h \
	common.h common.c

check_fixedpoint_SOURCES = check_fixedpoint.c
check_fixedpoint_LDADD = $(top_builddir)/src/lib/libfixedpoint.la $(LDADD)

if USE_SNMP
TESTS += check_snmp
check_snmp_SOURCES = check_snmp.c \
	$(top_srcdir)/src/daemon/lldpd.h \
	$(top_srcdir)/src/daemon/agent.h
LDADD += @NETSNMP_LIBS@
endif

check_PROGRAMS = $(TESTS)

endif

MOSTLYCLEANFILES = lldp_send_*.pcap cdp_send_*.pcap sonmp_send_*.pcap edp_send_*.pcap \
	ifdump.txt
