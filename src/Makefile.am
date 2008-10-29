sbin_PROGRAMS = lldpd lldpctl

COMMON = log.c ctl.c lldpd.h lldp.h cdp.h compat.h sonmp.h llc.h edp.h
lldpd_SOURCES = lldpd.c lldp.c cdp.c sonmp.c edp.c iov.c features.c client.c $(COMMON)
lldpctl_SOURCES = lldpctl.c $(COMMON)

lldpd_LDADD = @LIBOBJS@
lldpctl_LDADD = @LIBOBJS@

if USE_SNMP
lldpd_SOURCES += agent.c
lldpd_LDADD += @NETSNMP_LIB@
endif
