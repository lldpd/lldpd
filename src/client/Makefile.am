AM_CFLAGS = -I $(top_srcdir)/include

sbin_PROGRAMS = lldpctl
dist_man_MANS = lldpctl.8

lldpctl_SOURCES  = client.h lldpctl.c display.c actions.c \
	commands.c show.c \
	misc.c \
	writer.h text_writer.c kv_writer.c
lldpctl_LDADD    = \
	$(top_builddir)/src/libcommon-daemon-client.la \
	$(top_builddir)/src/lib/liblldpctl.la \
	@EDITLINE_LIBS@
lldpctl_CFLAGS   = $(AM_CFLAGS) @EDITLINE_CFLAGS@

if USE_XML
lldpctl_SOURCES += xml_writer.c
lldpctl_CFLAGS  += @XML2_CFLAGS@
lldpctl_LDADD   += @XML2_LIBS@
endif

if USE_JSON
lldpctl_SOURCES += json_writer.c
lldpctl_CFLAGS  += @JANSSON_CFLAGS@
lldpctl_LDADD   += @JANSSON_LIBS@
endif
