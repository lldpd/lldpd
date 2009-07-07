TESTS = check_pack check_lldp check_cdp

if HAVE_CHECK

check_PROGRAMS = $(TESTS)

check_pack_SOURCES = check_pack.c \
	$(top_builddir)/src/lldpd.h
check_pack_CFLAGS = @CHECK_CFLAGS@
check_pack_LDADD = $(top_builddir)/src/liblldpd.la @CHECK_LIBS@

check_lldp_SOURCES = check_lldp.c \
	$(top_builddir)/src/lldpd.h \
	common.h common.c
check_lldp_CFLAGS = @CHECK_CFLAGS@
check_lldp_LDADD = $(top_builddir)/src/liblldpd.la @CHECK_LIBS@

check_cdp_SOURCES = check_cdp.c \
	$(top_builddir)/src/lldpd.h \
	common.h common.c
check_cdp_CFLAGS = @CHECK_CFLAGS@
check_cdp_LDADD = $(top_builddir)/src/liblldpd.la @CHECK_LIBS@

if USE_SNMP
check_pack_LDADD += @NETSNMP_LIB@
check_lldp_LDADD += @NETSNMP_LIB@
check_cdp_LDADD += @NETSNMP_LIB@
endif

endif
