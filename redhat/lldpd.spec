# configure options

# Define with/without/bcond_without macros (needed for RHEL4)
%define with()		%{expand:%%{?with_%{1}:1}%%{!?with_%{1}:0}}
%define bcond_without()	%{expand:%%{!?_without_%{1}:%%global with_%{1} 1}}
%define bcond_with()	%{expand:%%{?_with_%{1}:%%global with_%{1} 1}}

# Conditional build options, disable with "--without xxx"
%bcond_without xml
%bcond_without cdp
%bcond_without edp
%bcond_without sonmp
%bcond_without fdp
%bcond_without lldpmed
%bcond_without dot1
%bcond_without dot3

# On RHEL < 5, disable SNMP, Net-SNMP installation seems broken
%if 0%{?rhel_version} > 0 && 0%{?rhel_version} < 500 || 0%{?centos_version} > 0 && 0%{?centos_version} < 500
%bcond_with snmp
%else
%bcond_without snmp
%endif

%define lldpd_user _lldpd
%define lldpd_group _lldpd
%define lldpd_chroot /var/run/lldpd

Summary: Implementation of IEEE 802.1ab (LLDP)
Name: lldpd
Version: 0.7.11
Release: 1%{?dist}
License: MIT
Group: System Environment/Daemons
URL: http://vincentbernat.github.com/lldpd/
Source0: http://media.luffy.cx/files/lldpd/%{name}-%{version}.tar.gz
Source1: lldpd.init%{?suse_version:.suse}
Source2: lldpd.sysconfig

BuildRequires: pkgconfig
BuildRequires: readline-devel
%if %{with snmp}
BuildRequires: net-snmp-devel
BuildRequires: openssl-devel
%{!?suse_version:BuildRequires: lm_sensors-devel}
%endif
%if %{with xml}
BuildRequires: libxml2-devel
%endif
%if 0%{?suse_version}
PreReq: %fillup_prereq %insserv_prereq pwdutils
%else
Requires(pre): /usr/sbin/groupadd /usr/sbin/useradd
Requires(post): chkconfig
Requires(preun): chkconfig
Requires(preun): initscripts
Requires(postun): initscripts
%endif

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%description
This implementation provides LLDP sending and reception, supports VLAN
and includes an SNMP subagent that can interface to an SNMP agent
through AgentX protocol.

LLDP is an industry standard protocol designed to supplant proprietary
Link-Layer protocols such as Extreme EDP (Extreme Discovery Protocol)
and CDP (Cisco Discovery Protocol). The goal of LLDP is to provide an
inter-vendor compatible mechanism to deliver Link-Layer notifications
to adjacent network devices.

This daemon is also able to deal with CDP, FDP, SONMP and EDP
protocol. It also handles LLDP-MED extension.

%package devel
Summary:  Implementation of IEEE 802.1ab - Tools and header files for developers
Group:    Development/Libraries
Requires: lldpd = %{version}-%{release}

%description devel
This package is required to develop alternate clients for lldpd.

%prep
%setup -q
%build
%configure \
%if %{with snmp}
   --with-snmp \
%endif
%if %{with xml}
   --with-xml \
%endif
%if %{with cdp}
   --enable-cdp \
%else
   --disable-cdp \
%endif
%if %{with edp}
   --enable-edp \
%else
   --disable-edp \
%endif
%if %{with sonmp}
   --enable-sonmp \
%else
   --disable-sonmp \
%endif
%if %{with fdp}
   --enable-fdp \
%else
   --disable-fdp \
%endif
%if %{with lldpmed}
   --enable-lldpmed \
%else
   --disable-lldpmed \
%endif
%if %{with dot1}
   --enable-dot1 \
%else
   --disable-dot1 \
%endif
%if %{with dot3}
   --enable-dot3 \
%else
   --disable-dot3 \
%endif
   --with-privsep-user=%lldpd_user \
   --with-privsep-group=%lldpd_group \
   --with-privsep-chroot=%lldpd_chroot \
   --with-systemdsystemunitdir=no \
   --with-sysusersdir=no \
   --prefix=%{_usr} \
   --localstatedir=%{_localstatedir} \
   --sysconfdir=%{_sysconfdir} \
   --libdir=%{_libdir} \
   --docdir=%{_docdir}/lldpd

[ -f %{_includedir}/net-snmp/agent/struct.h ] || touch src/struct.h
make %{?_smp_mflags}

%install
make install DESTDIR=$RPM_BUILD_ROOT
install -d -m770  $RPM_BUILD_ROOT/%lldpd_chroot
install -d $RPM_BUILD_ROOT/%{_initrddir}
install -m755 %{SOURCE1} $RPM_BUILD_ROOT/%{_initrddir}/lldpd
%if 0%{?suse_version}
mkdir -p ${RPM_BUILD_ROOT}/var/adm/fillup-templates
install -m700 %{SOURCE2} ${RPM_BUILD_ROOT}/var/adm/fillup-templates/sysconfig.lldpd
%else
install -d $RPM_BUILD_ROOT/etc/sysconfig
install -m644 %{SOURCE2} $RPM_BUILD_ROOT/etc/sysconfig/lldpd
%endif

%pre
# Create lldpd user/group
if getent group %lldpd_group >/dev/null 2>&1 ; then : ; else \
 %{_sbindir}/groupadd -r %lldpd_group > /dev/null 2>&1 || exit 1 ; fi
if getent passwd %lldpd_user >/dev/null 2>&1 ; then : ; else \
 %{_sbindir}/useradd -g %lldpd_group -M -r -s /bin/false \
 -c "LLDP daemon" -d %lldpd_chroot %lldpd_user 2> /dev/null \
 || exit 1 ; fi

%if 0%{?suse_version}
# Service management for SuSE

%post
/sbin/ldconfig
%{fillup_and_insserv lldpd}
%postun
/sbin/ldconfig
%restart_on_update lldpd
%insserv_cleanup
%preun
%stop_on_removal lldpd

%else
# Service management for Redhat/Centos

%post
/sbin/ldconfig
/sbin/chkconfig --add lldpd
%postun
/sbin/ldconfig
if [ "$1" -ge  "1" ]; then
   /sbin/service lldpd condrestart >/dev/null 2>&1 || :
fi
%preun
if [ "$1" = "0" ]; then
   /sbin/service lldpd stop > /dev/null 2>&1
   /sbin/chkconfig --del lldpd
fi

%endif

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%dir %{_docdir}/lldpd
%doc %{_docdir}/lldpd/NEWS
%doc %{_docdir}/lldpd/ChangeLog
%doc %{_docdir}/lldpd/README.md
%doc %{_docdir}/lldpd/CONTRIBUTE.md
%{_sbindir}/lldpd
%{_sbindir}/lldpctl
%{_sbindir}/lldpcli
%{_libdir}/liblldpctl.so.*
%doc %{_mandir}/man8/lldp*
%dir %attr(750,root,root) %lldpd_chroot
%config %{_sysconfdir}/lldpd.d/README.conf
%config %attr(755,root,root) %{_initrddir}/lldpd
%if 0%{?suse_version}
%attr(644,root,root) %{_var}/adm/fillup-templates/sysconfig.lldpd
%else
%config(noreplace) %{_sysconfdir}/sysconfig/lldpd
%endif

%files devel
%defattr(-,root,root)
%{_libdir}/liblldpctl.so
%{_libdir}/liblldpctl.a
%{_libdir}/liblldpctl.la
%{_libdir}/pkgconfig/lldpctl.pc
%{_includedir}/lldpctl.h
%{_includedir}/lldp-const.h

%changelog
* Wed Oct 08 2014 Vincent Bernat <bernat@luffy.cx> - 0.7.11-1
- New upstream version.

* Mon Jul 21 2014 Vincent Bernat <bernat@luffy.cx> - 0.7.10-1
- New upstream version.

* Wed May 28 2014 Vincent Bernat <bernat@luffy.cx> - 0.7.9-1
- New upstream version.

* Sun Apr 13 2014 Vincent Bernat <bernat@luffy.cx> - 0.7.8-1
- New upstream version.

* Fri Nov 10 2013 Vincent Bernat <bernat@luffy.cx> - 0.7.7-1
- New upstream version.

* Fri Jul 12 2013 Vincent Bernat <bernat@luffy.cx> - 0.7.6-1
- New upstream version.

* Sat Jun 22 2013 Vincent Bernat <bernat@luffy.cx> - 0.7.5-1
- New upstream version.

* Sun May 12 2013 Vincent Bernat <bernat@luffy.cx> - 0.7.3-1
- New upstream version.

* Fri Apr 19 2013 Vincent Bernat <bernat@luffy.cx> - 0.7.2-1
- New upstream version.

* Sat Jan 12 2013 Vincent Bernat <bernat@luffy.cx> - 0.7.1-1
- New upstream version.

* Sun Jan 06 2013 Vincent Bernat <bernat@luffy.cx> - 0.7.0-1
- New upstream version.
- Requires readline-devel.
- Ships lldpcli.

* Wed Sep 27 2012 Vincent Bernat <bernat@luffy.cx> - 0.6.1-1
- New upstream version
- Do not require libevent, use embedded copy.
- Provide a -devel package.

* Fri Jun 11 2010 Vincent Bernat <bernat@luffy.cx> - 0.5.1-1
- New upstream version
- Define bcond_without and with macros if not defined to be compatible
  with RHEL
- Requires useradd and groupadd
- Adapt to make it work with SuSE
- Provide an init script targetted at SuSE
- Build require lm_sensors-devel on RHEL

* Fri Mar 12 2010 Vincent Bernat <bernat@luffy.cx> - 0.5.0-1
- New upstream version
- Add XML support

* Tue May 19 2009 Vincent Bernat <bernat@luffy.cx> - 0.4.0-1
- Add variables
- Enable SNMP support
- Add _lldpd user creation
- Add initscript
- New upstream version

* Mon May 18 2009 Dean Hamstead <dean.hamstead@optusnet.com.au> - 0.3.3-1
- Initial attempt
