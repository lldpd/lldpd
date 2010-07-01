#
# lldp_CHECK_LIBEVENT
#

AC_DEFUN([lldp_CHECK_LIBEVENT], [
  LIBEVENT_URL=http://www.monkey.org/~provos/libevent/

  AC_MSG_CHECKING([how to compile with libevent])
  _save_LIBS="$LIBS"
  _save_CFLAGS="$CFLAGS"
  if test x"$1" = x -o x"$1" = x"yes"; then
     # Nothing specified, use default location
     LIBEVENT_LIBS="-levent"
  else
     if test -d "$1"; then
        # Directory, dynamic linking
        if test -d "$1/lib"; then
	   LIBEVENT_LIBS="-L$1/lib -levent"
        else
           LIBEVENT_LIBS="-L$1 -levent"
        fi
        if test -d "$1/include"; then
           LIBEVENT_CFLAGS="-I$1/include"
        else
           LIBEVENT_CFLAGS="-I$1"
        fi
     else if test -f "$1"; then
	# Static linking is a bit difficult, we need to "guess dependencies"
        LIBEVENT_LIBS="$1 -lrt"
        dir=`AS_DIRNAME(["$1"])`
        for includedir in "$dir/include" "$dir/../include" "$dir"; do
            if test -d "$includedir"; then
               LIBEVENT_CFLAGS="-I$includedir"
               break
            fi
        done
     else
        AC_MSG_RESULT(failed)
        AC_MSG_ERROR([*** non-existant directory ($1) specified for libevent!])
     fi
     fi
  fi
                
  # Can I compile and link it?
  LIBS="$LIBS $LIBEVENT_LIBS"
  CFLAGS="$LIBEVENT_CFLAGS $CFLAGS"
  AC_TRY_LINK([
@%:@include <sys/time.h>
@%:@include <sys/types.h>
@%:@include <event.h>], [ event_init(); ],
       [ libevent_linked=yes ], [ libevent_linked=no ])

  if test x"$libevent_linked" = x"yes"; then
    AC_SUBST([LIBEVENT_LIBS])
    AC_SUBST([LIBEVENT_CFLAGS])
    AC_MSG_RESULT([ok with "$LIBEVENT_LIBS $LIBEVENT_CFLAGS"])
  else
    AC_MSG_RESULT([failed with "$LIBEVENT_LIBS $LIBEVENT_CFLAGS"])
    AC_MSG_ERROR([
*** libevent is required. Grab it from $LIBEVENT_URL
*** or install libevent-dev package])
  fi

  LIBS="$_save_LIBS"
  CFLAGS="$_save_CFLAGS"
])
