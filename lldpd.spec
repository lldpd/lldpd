Summary: implementation of IEEE 802.1ab (LLDP)
Name: lldpd
Version: 0.3.3
Release: 1
License: BSD Like
Group: System Environment/Daemons
URL: https://trac.luffy.cx/lldpd/
Source0: http://www.luffy.cx/lldpd/lldpd-0.3.3.tar.gz 

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%description
This implementation provides LLDP sending and reception, supports VLAN and includes an SNMP subagent that can interface to an SNMP agent through AgentX protocol.

LLDP is an industry standard protocol designed to supplant proprietary Link-Layer protocols such as Extreme's EDP (Extreme Discovery Protocol) and CDP (Cisco Discovery Protocol). The goal of LLDP is to provide an inter-vendor compatible mechanism to deliver Link-Layer notifications to adjacent network devices.

This daemon is also able to deal with CDP, FDP, SONMP and EDP protocol. It also handles LLDP-MED extension.

%prep
%setup
./configure --prefix=/usr --localstatedir=/var --sysconfdir=/etc

%build
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc CHANGELOG 
%doc %_docdir/lldpd/README
%_sbindir/lldpd 
%_sbindir/lldpctl
%doc %_mandir/man8/lldp*

%changelog
* Mon May 18 2009 Dean Hamstead <dean.hamstead@optusnet.com.au> - 0.3.3-1
- Initial attempt
