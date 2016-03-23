AM_CFLAGS = -I $(top_srcdir)/include $(LLDP_CFLAGS)
AM_CPPFLAGS = $(LLDP_CPPFLAGS)
AM_LDFLAGS = $(LLDP_LDFLAGS)

lib_LTLIBRARIES = liblldpctl.la
include_HEADERS = lldpctl.h

noinst_LTLIBRARIES = libfixedpoint.la
libfixedpoint_la_SOURCES = fixedpoint.h fixedpoint.c

ATOM_FILES = \
	atoms/config.c atoms/dot1.c atoms/dot3.c \
	atoms/interface.c atoms/med.c atoms/mgmt.c atoms/port.c \
	atoms/custom.c atoms/chassis.c
NON_ATOM_FILES = \
	errors.c connection.c atom.c helpers.c
liblldpctl_la_SOURCES = \
	lldpctl.h atom.h helpers.h \
	$(NON_ATOM_FILES) \
	$(ATOM_FILES)
nodist_liblldpctl_la_SOURCES = atom-glue.h atom-glue.c
BUILT_SOURCES = atom-glue.h
liblldpctl_la_LIBADD  = $(top_builddir)/src/libcommon-daemon-lib.la libfixedpoint.la

atom-glue.h: $(ATOM_FILES) Makefile
	$(AM_V_GEN)(cat $^ | \
		$(SED) -n 's+^ATOM_BUILDER_REGISTER(\([^,]*\), *\([0-9]*\)).*+\2 \1+p' | \
		$(AWK) '{ atoms[$$2] = 1 } \
			 END { for (atom in atoms) { print "void init_atom_builder_"atom"(void);" } }' && \
		cat $^ | \
		$(SED) -n 's+^ATOM_MAP_REGISTER(\([^,]*\), *\([0-9]*\)).*+\2 \1+p' | \
		$(AWK) '{ atoms[$$2] = 1 } \
			 END { for (atom in atoms) { print "void init_atom_map_"atom"(void);" } }' ) \
		> $@.tmp
	@[ -s $@.tmp ]
	@mv $@.tmp $@
atom-glue.c: $(ATOM_FILES) Makefile atom-glue.h
	$(AM_V_GEN)(cat $^ | \
		$(SED) -n 's+^ATOM_BUILDER_REGISTER(\([^,]*\), *\([0-9]*\)).*+\2 \1+p' | \
		sort -n | \
		$(AWK) '{ atoms[$$2] = 1 } \
			 END { print "#include \"lldpctl.h\""; \
                               print "#include \"atom.h\""; \
                               print "void init_atom_builder() {"; \
                               print " static int init = 0; if (init) return; init++;"; \
			       for (atom in atoms) { print " init_atom_builder_"atom"();" } \
			       print "}"; }' && \
		cat $^ | \
		$(SED) -n 's+^ATOM_MAP_REGISTER(\([^,]*\), *\([0-9]*\)).*+\2 \1+p' | \
		sort -n | \
		$(AWK) '{ atoms[$$2] = 1 } \
			 END { print "void init_atom_map() {"; \
                               print " static int init = 0; if (init) return; init++;"; \
			       for (atom in atoms) { print " init_atom_map_"atom"();" } \
			       print "}"; }' ) \
		> $@.tmp
	@[ -s $@.tmp ]
	@mv $@.tmp $@
CLEANFILES = atom-glue.h atom-glue.c

# -version-info format is `current`:`revision`:`age`. For more details, see:
#   https://www.sourceware.org/autobook/autobook/autobook_61.html#Library-Versioning
#
# -version-number could be computed from -version-info, mostly major
# is `current` - `age`, minor is `age` and revision is `revision' and
# major.minor should be used when updaing lldpctl.map.
liblldpctl_la_LDFLAGS = $(AM_LDFLAGS) -version-info 12:0:8
liblldpctl_la_DEPENDENCIES = libfixedpoint.la

if HAVE_LD_VERSION_SCRIPT
liblldpctl_la_DEPENDENCIES += lldpctl.map
liblldpctl_la_LDFLAGS += -Wl,--version-script=$(srcdir)/lldpctl.map
else
liblldpctl_la_LDFLAGS += -export-symbols-regex '^lldpctl_'
endif

pkgconfig_DATA = lldpctl.pc

TEMPLATES  = lldpctl.pc
EXTRA_DIST = lldpctl.pc.in lldpctl.map
CLEANFILES += $(TEMPLATES)
lldpctl.pc: lldpctl.pc.in
include $(top_srcdir)/edit.am
