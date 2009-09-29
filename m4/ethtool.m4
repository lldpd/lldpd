#
# lldp_CHECK_HEADER_ETHTOOL
#
AC_DEFUN([lldp_CHECK_HEADER_ETHTOOL], [
        AC_CACHE_CHECK([for linux/ethtool.h], mac_cv_header_ethtool_h, [
                AC_COMPILE_IFELSE([
                        AC_LANG_SOURCE([
AC_INCLUDES_DEFAULT
@%:@include <linux/ethtool.h>
                        ])
                ], [mac_cv_header_ethtool_h=yes], [mac_cv_header_ethtool_h=no]
                )
                if test "$mac_cv_header_ethtool_h" = no; then
                        AC_COMPILE_IFELSE([
                                AC_LANG_SOURCE([
AC_INCLUDES_DEFAULT
@%:@define u8  uint8_t
@%:@define s8  int8_t
@%:@define u16 uint16_t
@%:@define s16 int16_t
@%:@define u32 uint32_t
@%:@define s32 int32_t
@%:@define u64 uint64_t
@%:@define s64 int64_t
@%:@include <linux/ethtool.h>
                                ])
                        ],
                        [mac_cv_header_ethtool_h="yes (with type munging)"],
                        [mac_cv_header_ethtool_h=no]
                        )
                ])
        fi
        if test "$mac_cv_header_ethtool_h" = "yes (with type munging)"; then
                AC_DEFINE(u8,  uint8_t,  [Define to the type u8 should expand to.])
                AC_DEFINE(s8,  int8_t,   [Define to the type u8 should expand to.])
                AC_DEFINE(u16, uint16_t, [Define to the type u16 should expand to.])
                AC_DEFINE(s16, int16_t,  [Define to the type u16 should expand to.])
                AC_DEFINE(u32, uint32_t, [Define to the type u32 should expand to.])
                AC_DEFINE(s32, int32_t,  [Define to the type u32 should expand to.])
                AC_DEFINE(u64, uint64_t, [Define to the type u64 should expand to.])
                AC_DEFINE(s64, int64_t,  [Define to the type u64 should expand to.])
        fi
        if test "$mac_cv_header_ethtool_h" = no; then
                :
        else
                AC_DEFINE(HAVE_ETHTOOL_H, 1, [Define to 1 if you have the <linux/ethtool.h> header file.])
        fi
])
