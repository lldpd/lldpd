#
# lldp_CHECK_SNMP
#
AC_DEFUN([lldp_CHECK_SNMP], [
  AS_IF([test x"$with_snmp" != x"no"], [
   AC_PATH_TOOL([NETSNMP_CONFIG], [net-snmp-config], [no])
   AS_IF([test x"$NETSNMP_CONFIG" = x"no"], [
      dnl No luck
      AS_IF([test x"$with_snmp" = x"yes"], [
         AC_MSG_FAILURE([*** no NetSNMP support found])
      ])
      with_snmp=no
   ], [
      dnl Check it is working as expected
      NETSNMP_LIBS=`${NETSNMP_CONFIG} --agent-libs`
      NETSNMP_CFLAGS=`${NETSNMP_CONFIG} --base-cflags`

      _save_flags="$CFLAGS"
      _save_libs="$LIBS"
      CFLAGS="$CFLAGS ${NETSNMP_CFLAGS}"
      LIBS="$LIBS ${NETSNMP_LIBS}"
      AC_MSG_CHECKING([whether C compiler supports flag "${NETSNMP_CFLAGS} ${NETSNMP_LIBS}" from Net-SNMP])
      AC_LINK_IFELSE([AC_LANG_PROGRAM([
int main(void);
],
[
{
  return 0;
}
])],[
        AC_MSG_RESULT(yes)
        dnl Is Net-SNMP usable?
        AC_CHECK_LIB([netsnmp], [snmp_register_callback], [
          dnl Do we have subagent support?
          AC_CHECK_FUNCS([netsnmp_enable_subagent], [
            dnl Yes, we need to check a few more things
            AC_SUBST([NETSNMP_LIBS])
            AC_SUBST([NETSNMP_CFLAGS])
            AC_DEFINE_UNQUOTED([USE_SNMP], 1, [Define to indicate to enable SNMP support])
            with_snmp=yes

            dnl Should we use f_create_from_tstring_new or f_create_from_tstring?
            AC_CHECK_MEMBERS([netsnmp_tdomain.f_create_from_tstring_new],,,[
@%:@include <net-snmp/net-snmp-config.h>
@%:@include <net-snmp/net-snmp-includes.h>
@%:@include <net-snmp/library/snmp_transport.h>
            ])
            dnl Do we have a usable <net-snmp/agent/util_funcs.h> header?
            AC_CHECK_HEADERS([net-snmp/agent/util_funcs.h],,,[
@%:@include <net-snmp/net-snmp-config.h>
@%:@include <net-snmp/net-snmp-includes.h>
@%:@include <net-snmp/library/snmp_transport.h>
@%:@include <net-snmp/agent/net-snmp-agent-includes.h>
@%:@include <net-snmp/agent/snmp_vars.h>
            ])
            dnl Can we use snmp_select_info2?
            AC_CHECK_FUNCS([snmp_select_info2])
          ],[
            AS_IF([test x"$with_snmp" = x"yes"], [
              AC_MSG_ERROR([*** no subagent support in net-snmp])
            ])
            with_snmp=no
          ])
        ],[
          AS_IF([test x"$with_snmp" = x"yes"], [
            AC_MSG_ERROR([*** unable to use net-snmp])
          ])
          with_snmp=no
        ])
      ],[
        AC_MSG_RESULT(no)
        AS_IF([test x"$with_snmp" = x"yes"], [
          AC_MSG_ERROR([*** incorrect CFLAGS from net-snmp-config])
        ])
        with_snmp=no
      ])

      CFLAGS="$_save_flags"
      LIBS="$_save_libs"
   ])
  ])
])
