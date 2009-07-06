TESTS = check_pack check_lldp

if HAVE_CHECK

check_PROGRAMS = check_pack check_lldp

check_pack_SOURCES = check_pack.c \
	$(top_builddir)/src/lldpd.h
check_pack_CFLAGS = @CHECK_CFLAGS@
check_pack_LDADD = $(top_builddir)/src/liblldpd.la @CHECK_LIBS@

check_lldp_SOURCES = check_lldp.c \
	$(top_builddir)/src/lldpd.h
check_lldp_CFLAGS = @CHECK_CFLAGS@
check_lldp_LDADD = $(top_builddir)/src/liblldpd.la @CHECK_LIBS@

if USE_SNMP
check_pack_LDADD += @NETSNMP_LIB@
check_lldp_LDADD += @NETSNMP_LIB@
endif

endif
