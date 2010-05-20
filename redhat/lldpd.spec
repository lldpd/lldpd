# configure options

# Conditional build options, disable with "--without xxx"
%bcond_without snmp
%bcond_without xml
%bcond_without cdp
%bcond_without edp
%bcond_without sonmp
%bcond_without fdp
%bcond_without lldpmed
%bcond_without dot1
%bcond_without dot3

%define lldpd_user _lldpd
%define lldpd_group _lldpd
%define lldpd_chroot /var/run/lldpd

Summary: implementation of IEEE 802.1ab (LLDP)
Name: lldpd
Version: 0.5.0
Release: 1%{?dist}
License: MIT
Group: System Environment/Daemons
URL: https://trac.luffy.cx/lldpd/
Source0: http://www.luffy.cx/lldpd/%{name}-%{version}.tar.gz 
Source1: lldpd.init
Source2: lldpd.sysconfig

%if %{with snmp}
BuildRequires: net-snmp-devel
Requires:      net-snmp
BuildRequires: openssl-devel
Requires:      openssl
%endif
%if %{with xml}
BuildRequires: libxml2-devel
Requires:      libxml2
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
   --prefix=/usr --localstatedir=%lldpd_chroot --sysconfdir=/etc --libdir=%{_libdir} \
   --docdir=%{_docdir}/lldpd

[ -f /usr/include/net-snmp/agent/struct.h ] || touch src/struct.h
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
install -d -m770  $RPM_BUILD_ROOT/%lldpd_chroot
install -d $RPM_BUILD_ROOT/etc/rc.d/init.d
install -d $RPM_BUILD_ROOT/etc/sysconfig
install -m644 %{SOURCE2} $RPM_BUILD_ROOT/etc/sysconfig/lldpd
install -m755 %{SOURCE1} $RPM_BUILD_ROOT/etc/rc.d/init.d/lldpd

%pre
# Create lldpd user/group
if getent group %lldpd_group >/dev/null 2>&1 ; then : ; else \
 /usr/sbin/groupadd -r %lldpd_group > /dev/null 2>&1 || exit 1 ; fi
if getent passwd %lldpd_user >/dev/null 2>&1 ; then : ; else \
 /usr/sbin/useradd -g %lldpd_group -M -r -s /bin/false \
 -c "LLDP daemon" -d %lldpd_chroot %lldpd_user 2> /dev/null \
 || exit 1 ; fi

%post
/sbin/chkconfig --add lldpd

%postun
if [ "$1" -ge  "1" ]; then
   /etc/rc.d/init.d/lldpd  condrestart >/dev/null 2>&1
fi

%preun
if [ "$1" = "0" ]; then
   /sbin/chkconfig --del lldpd
fi

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc %_docdir/lldpd/CHANGELOG 
%doc %_docdir/lldpd/README
%_sbindir/lldpd 
%_sbindir/lldpctl
%doc %_mandir/man8/lldp*
%dir %attr(750,root,root) %lldpd_chroot
%config(noreplace) /etc/sysconfig/lldpd
%attr(755,root,root) /etc/rc.d/init.d/*

%changelog
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
