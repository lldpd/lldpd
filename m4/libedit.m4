#
# lldp_CHECK_EDITLINE
#

AC_DEFUN([lldp_CHECK_EDITLINE], [
  _save_LIBS="$LIBS"
  _save_CFLAGS="$CFLAGS"

  # First, try with pkg-config
  PKG_CHECK_MODULES([EDITLINE], [libedit >= 2.9], [], [
    # Nothing appropriate. Maybe it is installed anyway.
    AC_CHECK_HEADER([histedit.h], [],
      [AC_MSG_ERROR([*** unable to find editline/libedit])])
    EDITLINE_CFLAGS=""
    EDITLINE_LIBS="-ledit -lcurses"
  ])

  # Check if everything works as expected
  LIBS="$LIBS $EDITLINE_LIBS"
  CFLAGS="$CFLAGS $EDITLINE_CFLAGS"
  AC_MSG_CHECKING([if libedit version is compatible])
  AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([[
@%:@include <stdlib.h>
@%:@include <histedit.h>
    ]], [[
int i = H_SETSIZE; (void)i;
el_init("", NULL, NULL, NULL);
exit(0);
    ]])],
    [ AC_MSG_RESULT([yes]) ],
    [ AC_MSG_RESULT([no])
      AC_MSG_ERROR([*** libedit does not work as expected])])])

  LIBS="$_save_LIBS"
  CFLAGS="$_save_CFLAGS"

  AC_SUBST([EDITLINE_CFLAGS])
  AC_SUBST([EDITLINE_LIBS])
])
