#
# lldp_CHECK_OS
#
# List of supported OS.
#
AC_DEFUN([lldp_DEFINE_OS], [dnl
  case $host_os in
    $1)
      os="$2"
      AC_DEFINE_UNQUOTED(HOST_OS_$3, 1, [Host operating system is $2])
      ;;
  esac
  AM_CONDITIONAL(HOST_OS_$3, test x"$os" = x"$2")dnl
])

AC_DEFUN([lldp_CHECK_OS], [
  AC_CANONICAL_HOST
  AC_MSG_CHECKING([if host OS is supported])

  lldp_DEFINE_OS(linux*, Linux, LINUX)
  lldp_DEFINE_OS(freebsd*|kfreebsd*, FreeBSD, FREEBSD)
  lldp_DEFINE_OS(dragonfly*, [DragonFly BSD], DRAGONFLY)
  lldp_DEFINE_OS(openbsd*, OpenBSD, OPENBSD)
  lldp_DEFINE_OS(netbsd*, NetBSD, NETBSD)
  lldp_DEFINE_OS(darwin*, [Mac OS X], OSX)

  if test x"$os" = x; then
     AC_MSG_RESULT(no)
     AC_MSG_ERROR([*** unsupported OS $host_os])
  fi
  AC_MSG_RESULT([yes ($os)])
])
