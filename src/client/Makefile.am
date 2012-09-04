sbin_PROGRAMS = lldpctl
dist_man_MANS = lldpctl.8

lldpctl_SOURCES  = client.h lldpctl.c display.c writer.h text_writer.c kv_writer.c actions.c
lldpctl_LDADD    = $(top_builddir)/src/libcommon-daemon-client.la $(top_builddir)/src/lib/liblldpctl.la

if USE_XML
lldpctl_SOURCES += xml_writer.c
lldpctl_CFLAGS   = @XML2_CFLAGS@
lldpctl_LDADD   += @XML2_LIBS@
endif
