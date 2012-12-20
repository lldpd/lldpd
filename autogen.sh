#!/bin/sh

set -e

[ ! -d .gitmodules ] || {
    echo "autogen.sh: updating git submodules"
    git submodule init
    git submodule update
}

echo "autogen.sh: start libtoolize to get ltmain.sh"
libtoolize --copy --force
echo "autogen.sh: reconfigure with autoreconf"
autoreconf -vif -I m4 || {
    echo "autogen.sh: autoreconf has failed ($?), let's do it manually"
    for dir in . *; do
        [ -d "$dir" ] || continue
        [ -f "$dir"/configure.ac ] || [ -f "$dir"/configure.in ] || continue
	echo "autogen.sh: configure `basename \`readlink -f $dir\``"
	(cd "$dir" && aclocal -I m4)
	(cd "$dir" && libtoolize --automake --copy --force)
	(cd "$dir" && aclocal -I m4)
	(cd "$dir" && autoconf --force)
	(cd "$dir" && autoheader)
	(cd "$dir" && automake --add-missing --copy --force-missing)
    done
}

echo "autogen.sh: for the next step, run ./configure"

exit 0
