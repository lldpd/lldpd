#
# lldp_SYSTEMTAP
#
# Check for DTrace/Systemtap support

AC_DEFUN([lldp_SYSTEMTAP], [
  # Enable systemtap support
  lldp_ARG_ENABLE([dtrace], [systemtap/DTrace trace support], [no])
  AM_CONDITIONAL([ENABLE_SYSTEMTAP], [test x"$enable_dtrace" = x"yes"])
  AS_IF([test x"$enable_dtrace" = x"yes"], [
     AC_CHECK_PROGS(DTRACE, dtrace)
     AS_IF([test -z "$DTRACE"], [
       AC_MSG_ERROR([*** dtrace command not found])
     ])
     AC_CHECK_HEADER([sys/sdt.h],,[AC_MSG_ERROR([*** no sys/sdt.h header found])])
  ])
])
