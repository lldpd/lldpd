#!/bin/sh

set -e

[ ! -d .gitmodules ] || {
    echo "autogen.sh: updating git submodules"
    git submodule init
    git submodule update
}

case "$(uname)" in
    Darwin)
        LIBTOOLIZE=${LIBTOOLIZE:-glibtoolize}
        ;;
    *)
        LIBTOOLIZE=${LIBTOOLIZE:-libtoolize}
        ;;
esac
AUTORECONF=${AUTORECONF:-autoreconf}
ACLOCAL=${ACLOCAL:-aclocal}
AUTOCONF=${AUTOCONF:-autoconf}
AUTOHEADER=${AUTOHEADER:-autoheader}
AUTOMAKE=${AUTOMAKE:-automake}

echo "autogen.sh: start libtoolize to get ltmain.sh"
${LIBTOOLIZE} --copy --force
echo "autogen.sh: reconfigure with autoreconf"
${AUTORECONF} -vif -I m4 || {
    echo "autogen.sh: autoreconf has failed ($?), let's do it manually"
    for dir in $PWD *; do
        [ -d "$dir" ] || continue
        [ -f "$dir"/configure.ac ] || [ -f "$dir"/configure.in ] || continue
	echo "autogen.sh: configure `basename $dir`"
	(cd "$dir" && ${ACLOCAL} -I m4)
	(cd "$dir" && ${LIBTOOLIZE} --automake --copy --force)
	(cd "$dir" && ${ACLOCAL} -I m4)
	(cd "$dir" && ${AUTOCONF} --force)
	(cd "$dir" && ${AUTOHEADER})
	(cd "$dir" && ${AUTOMAKE} --add-missing --copy --force-missing)
    done
}

echo "autogen.sh: for the next step, run ./configure"

exit 0
