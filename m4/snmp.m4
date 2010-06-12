#
# lldp_CHECK_SNMP
#


AC_DEFUN([lldp_CHECK_SNMP], [
   AC_PATH_TOOL([NETSNMP_CONFIG], [net-snmp-config], [no])
   if test x"$NETSNMP_CONFIG" = x"no"; then
      AC_MSG_ERROR([*** unable to find net-snmp-config])
   fi
   NETSNMP_LIBS=`${NETSNMP_CONFIG} --agent-libs`
   NETSNMP_CFLAGS="`${NETSNMP_CONFIG} --base-cflags` -DNETSNMP_NO_INLINE"

   _save_flags="$CFLAGS"
   CFLAGS="$CFLAGS ${NETSNMP_CFLAGS}"
   AC_MSG_CHECKING([whether C compiler supports flag "${NETSNMP_CFLAGS}" from Net-SNMP])
   AC_LINK_IFELSE([AC_LANG_PROGRAM([
int main(void);
],
[
{
  return 0;
}
])],[AC_MSG_RESULT(yes)],[
AC_MSG_RESULT(no)
AC_MSG_ERROR([*** incorrect CFLAGS from net-snmp-config])])
   AC_CHECK_LIB([netsnmp], [snmp_register_callback], [:],
       [AC_MSG_ERROR([*** unable to use net-snmp])], ${NETSNMP_LIBS})
   AC_SUBST([NETSNMP_LIBS])
   AC_SUBST([NETSNMP_CFLAGS])
   AC_DEFINE_UNQUOTED([USE_SNMP], 1, [Define to indicate to enable SNMP support])
   AC_CHECK_MEMBERS([netsnmp_tdomain.f_create_from_tstring_new],,,
	[
@%:@include <net-snmp/net-snmp-config.h>
@%:@include <net-snmp/net-snmp-includes.h>
@%:@include <net-snmp/library/snmp_transport.h>
])

   CFLAGS="$_save_flags"
])
