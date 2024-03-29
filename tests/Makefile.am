AM_CFLAGS = -I $(top_srcdir)/include $(LLDP_CFLAGS)
AM_CPPFLAGS = $(LLDP_CPPFLAGS)
AM_LDFLAGS = $(LLDP_LDFLAGS) $(LLDP_BIN_LDFLAGS)

check_PROGRAMS = decode
decode_SOURCES = decode.c \
	$(top_srcdir)/src/daemon/lldpd.h \
	pcap-hdr.h

LDADD = $(top_builddir)/src/daemon/liblldpd.la @libevent_LDFLAGS@
if ENABLE_SYSTEMTAP
LDADD += $(top_builddir)/src/daemon/probes.o
endif
if USE_SNMP
LDADD += @NETSNMP_LIBS@
endif

if HAVE_CHECK

TESTS = check_marshal check_pattern check_bitmap check_fixedpoint \
	check_lldp check_cdp check_sonmp check_edp
AM_CFLAGS += @check_CFLAGS@ -Wno-format-extra-args
LDADD += @check_LIBS@

check_marshal_SOURCES = check_marshal.c \
	$(top_srcdir)/src/marshal.h \
	check-compat.h

check_pattern_SOURCES = check_pattern.c \
	$(top_srcdir)/src/daemon/lldpd.h

check_bitmap_SOURCES = check_bitmap.c \
	$(top_srcdir)/src/daemon/lldpd.h

check_lldp_SOURCES = check_lldp.c \
	$(top_srcdir)/src/daemon/lldpd.h \
	common.h common.c check-compat.h pcap-hdr.h

check_cdp_SOURCES = check_cdp.c \
	$(top_srcdir)/src/daemon/lldpd.h \
	common.h common.c check-compat.h pcap-hdr.h

check_sonmp_SOURCES = check_sonmp.c \
	$(top_srcdir)/src/daemon/lldpd.h \
	common.h common.c check-compat.h pcap-hdr.h

check_edp_SOURCES = check_edp.c \
	$(top_srcdir)/src/daemon/lldpd.h \
	common.h common.c check-compat.h pcap-hdr.h

check_fixedpoint_SOURCES = check_fixedpoint.c
check_fixedpoint_LDADD = $(top_builddir)/src/lib/libfixedpoint.la $(LDADD)

if USE_SNMP
TESTS += check_snmp
check_snmp_SOURCES = check_snmp.c \
	$(top_srcdir)/src/daemon/lldpd.h \
	$(top_srcdir)/src/daemon/agent.h
endif

check_PROGRAMS += $(TESTS)

endif

if ENABLE_FUZZ_DECODE
noinst_PROGRAMS = fuzz_lldp fuzz_cdp fuzz_sonmp fuzz_edp

fuzz_lldp_SOURCES = fuzz_lldp.c \
	$(top_srcdir)/src/daemon/lldpd.h
fuzz_lldp_LDADD = $(top_builddir)/src/daemon/liblldpd.la $(LDADD) $(FUZZ_DECODE_ENGINE)

fuzz_cdp_SOURCES = fuzz_cdp.c \
	$(top_srcdir)/src/daemon/lldpd.h
fuzz_cdp_LDADD = $(top_builddir)/src/daemon/liblldpd.la $(LDADD) $(FUZZ_DECODE_ENGINE)

fuzz_sonmp_SOURCES = fuzz_sonmp.c \
	$(top_srcdir)/src/daemon/lldpd.h
fuzz_sonmp_LDADD = $(top_builddir)/src/daemon/liblldpd.la $(LDADD) $(FUZZ_DECODE_ENGINE)

fuzz_edp_SOURCES = fuzz_edp.c \
	$(top_srcdir)/src/daemon/lldpd.h
fuzz_edp_LDADD = $(top_builddir)/src/daemon/liblldpd.la $(LDADD) $(FUZZ_DECODE_ENGINE)
endif

MOSTLYCLEANFILES = *.pcap
