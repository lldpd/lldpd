#
# lldp_CHECK_LIBEVENT
#

AC_DEFUN([lldp_CHECK_LIBEVENT], [
  LIBEVENT_URL=http://libevent.org/
  _save_LIBS="$LIBS"
  _save_CFLAGS="$CFLAGS"
  _save_CC="$CC"

  # First, try with pkg-config
  PKG_CHECK_MODULES([LIBEVENT], [libevent >= 1.4.3], [], [:])

  AC_MSG_CHECKING([how to compile with libevent])
  if test x"$1" = x -o x"$1" = x"yes"; then
     # Nothing specified, use default location from pkg-config
     :
  else
     # Black magic....
     if test -d "$1"; then
        libevent_dir=`readlink -f "$1"`
        # Directory, dynamic linking
        if test -d "${libevent_dir}/lib"; then
	   LIBEVENT_LIBS="-L${libevent_dir}/lib -levent"
        else
           LIBEVENT_LIBS="-L${libevent_dir} -levent"
        fi
        if test -d "${libevent_dir}/include"; then
           LIBEVENT_CFLAGS="-I${libevent_dir}/include"
        else
           LIBEVENT_CFLAGS="-I${libevent_dir}"
        fi
     else if test -f "$1"; then
        LIBEVENT_LIBS=`readlink -f "$1"`
        dir=`AS_DIRNAME(["$1"])`
        for includedir in "$dir/include" "$dir/../include" "$dir"; do
            if test -d "$includedir"; then
               LIBEVENT_CFLAGS=-I`readlink -f "$includedir"`
               break
            fi
        done
     else
        AC_MSG_RESULT(failed)
        AC_MSG_ERROR([*** non-existant directory ($1) specified for libevent!])
     fi
     fi
  fi
                
  # Can I compile and link it? We need to use libtool
  LIBS="$LIBS $LIBEVENT_LIBS"
  CFLAGS="$LIBEVENT_CFLAGS $CFLAGS"
  CC="${SHELL-/bin/sh} libtool link $CC"
  AC_TRY_LINK([
@%:@include <sys/time.h>
@%:@include <sys/types.h>
@%:@include <event2/event.h>], [ event_base_new(); ],
       [ libevent_linked=yes ], [ libevent_linked=no ])

  if test x"$libevent_linked" = x"yes"; then
    AC_SUBST([LIBEVENT_LIBS])
    AC_SUBST([LIBEVENT_CFLAGS])
    AC_MSG_RESULT([ok with $LIBEVENT_LIBS $LIBEVENT_CFLAGS])
  else
    if test x"$LIBEVENT_LIBS" = x; then
      AC_MSG_RESULT([no libevent])
    else
      AC_MSG_RESULT([failed with $LIBEVENT_LIBS $LIBEVENT_CFLAGS])
    fi
    AC_MSG_ERROR([
*** libevent 2.x is required. Grab it from $LIBEVENT_URL
*** or install libevent-dev package])
  fi

  CC="$_save_CC"
  LIBS="$_save_LIBS"
  CFLAGS="$_save_CFLAGS"
])
