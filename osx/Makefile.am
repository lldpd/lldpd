EXTRA_DIST  = resources lipo
EXTRA_DIST += distribution.xml.in im.bernat.lldpd.plist.in scripts/postinstall.in scripts/preinstall.in
TEMPLATES   = distribution.xml    im.bernat.lldpd.plist    scripts/postinstall    scripts/preinstall

if HOST_OS_OSX

# What we need to build the package
PKGBUILD=/usr/bin/pkgbuild
PRODUCTBUILD=/usr/bin/productbuild
requirements:
	@test -x $(PKGBUILD) || { echo "Needs pkgbuild ($(PKGBUILD))." ; exit 2 ; }
	@test -x $(PRODUCTBUILD) || { echo "Needs productbuild ($(PRODUCTBUILD))." ; exit 2 ; }

PKG_NAME=@PACKAGE@-@VERSION@.pkg
PKG_TITLE=@PACKAGE@ @VERSION@
PKG_DIR=@PACKAGE@-@VERSION@
ARCHS=@host_cpu@

# Main target is `pkg`
pkg: requirements ../$(PKG_NAME)
	@echo "The package has been built in ../$(PKG_NAME)."

# This is the package (to be built with productbuild)
../$(PKG_NAME): pkg.1/$(PKG_NAME) distribution.xml resources
	$(PRODUCTBUILD) \
		--distribution distribution.xml \
		--resources resources \
		--package-path pkg.1 \
		--version @VERSION@ \
		$@

# This is a component. We only have one. We could have more and
# provide optional components to be installed.
pkg.1/$(PKG_NAME): $(PKG_DIR) scripts
	[ -d pkg.1 ] || mkdir pkg.1
	chmod +x scripts/postinstall scripts/preinstall
	$(PKGBUILD) \
		--root $(PKG_DIR) \
		--identifier im.bernat.@PACKAGE@.daemon \
		--version @VERSION@ \
		--ownership recommended \
		--scripts scripts \
		$@

$(PKG_DIR): stamp-$(PKG_DIR)
stamp-$(PKG_DIR): $(ARCHS:%=%/$(PKG_DIR))
	$(srcdir)/lipo $(PKG_DIR) $^
	touch $@

pkg_curarch = $(@:stamp-%=%)
$(ARCHS:%=%/$(PKG_DIR)): %/$(PKG_DIR): stamp-%
$(ARCHS:%=stamp-%): stamp-%: im.bernat.lldpd.plist
	[ -d $(pkg_curarch) ] || mkdir -p $(pkg_curarch)
	(cd $(pkg_curarch) && \
		$(abs_top_srcdir)/configure @CONFIGURE_ARGS@ \
			CC="@CC@ -arch $(pkg_curarch)" \
			CPP="@CPP@")
	(cd $(pkg_curarch) && \
		$(MAKE) install DESTDIR=$(abs_builddir)/$(pkg_curarch)/$(PKG_DIR))
	touch $@

# Install launchd plist
if HAVE_LAUNCHDDAEMONSDIR
launchddaemons_DATA = im.bernat.lldpd.plist
endif

CLEANFILES  = $(TEMPLATES)
distribution.xml: distribution.xml.in
im.bernat.lldpd.plist: im.bernat.lldpd.plist.in
scripts/postinstall: scripts/postinstall.in
scripts/preinstall: scripts/preinstall.in
include $(top_srcdir)/edit.am

.PHONY: pkg requirements

endif
