EXTRA_DIST = resources

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
	$(PKGBUILD) \
		--root $(PKG_DIR) \
		--identifier im.bernat.@PACKAGE@.daemon \
		--version @VERSION@ \
		--ownership recommended \
		--scripts scripts \
		$@
$(PKG_DIR): stamp-$(PKG_DIR)
stamp-$(PKG_DIR): im.bernat.lldpd.plist
	$(MAKE) -C $(top_builddir) install DESTDIR=$(abs_builddir)/$(PKG_DIR)
	touch $@

# Install launchd plist
install-data-local:
	install -m 0755 -d $(DESTDIR)/Library/LaunchDaemons
	install -m 0644 im.bernat.lldpd.plist $(DESTDIR)/Library/LaunchDaemons
uninstall-local:
	rm -rf $(DESTDIR)/Library/LaunchDaemons
clean-local:
	rm -rf $(PKG_DIR)
	rm -f stamp-$(PKG_DIR)
	rm -rf pkg.1
	rm -f ../$(PKG_NAME)

.PHONY: pkg requirements

endif
