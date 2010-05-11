#
# lldp_CHECK_FD_SETSIZE
#
AC_DEFUN([lldp_CHECK_FD_SETSIZE],[
  AC_CACHE_CHECK([real value of FD_SETSIZE], lldp_cv_check_fd_setsize, [
    AC_RUN_IFELSE([
       AC_LANG_PROGRAM(
        [
@%:@include <stdio.h>
@%:@include <sys/select.h>
@%:@include <sys/time.h>
@%:@include <sys/types.h>
@%:@include <unistd.h>
	],
	[
	FILE *fd;
	if ((fd = fopen("conftest.out", "w")) == NULL) {
	   printf("Unable to create file conftest.out");
	   return 1;
        }
	fprintf(fd, "%d\n", FD_SETSIZE);
	fclose(fd);
	])],
       [ lldp_cv_check_fd_setsize=`cat conftest.out` ],
       [ lldp_cv_check_fd_setsize="no" ],
       [ lldp_cv_check_fd_setsize="no" ])])
  if test x"$lldp_cv_check_fd_setsize" = x"no"; then
     AC_DEFINE([LLDPD_FD_SETSIZE], [FD_SETSIZE], [FD_SETSIZE for select()])
  else
     AC_DEFINE_UNQUOTED([LLDPD_FD_SETSIZE], $lldp_cv_check_fd_setsize,
               [FD_SETSIZE for select()])
  fi
])
