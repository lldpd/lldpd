Summary: lldpd is a lldp daemon for GNU/Linux and implements both reception and sending 
Name: lldpd
Version: 0.3.3
Release: 1
License: BSD Like
Group: System Environment/Daemons
URL: http://www.luffy.cx/
Source0: http://www.luffy.cx/lldpd/lldpd-0.3.3.tar.gz 

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: autoconf, automake

%description
LLDP (Link Layer Discovery Protocol) is an industry standard protocol designed to supplant proprietary Link-Layer protocols such as Extreme's EDP (Extreme Discovery Protocol) and CDP (Cisco Discovery Protocol). The goal of LLDP is to provide an inter-vendor compatible mechanism to deliver Link-Layer notifications to adjacent network devices.

lldpd is a lldp daemon for GNU/Linux and implements both reception and sending. It supports both LLDP and LLDP-MED (contributed by Michael Hanig). It also implements an SNMP subagent for net-snmp to get local and remote LLDP information. The LLDP MIB is partially implemented but the most useful tables are here.

lldpd supports bridge, vlan and bonding. bonding need to be done on real physical devices, not on bridges, vlans, etc. However, vlans can be mapped on the bonding device. You can bridge vlan but not add vlans on bridges. More complex setups may give false results.

A small utility, lldpctl allows to query information collected through the command line.

lldpd also implements CDP (Cisco Discovery Protocol), FDP (Foundry Discovery Protocol), SONMP (Nortel Discovery Protocol) and EDP (Extreme Discovery Protocol). However, recent versions of IOS should support LLDP and most Extreme stuff support LLDP. When a EDP, CDP or SONMP frame is received on a given interface, lldpd starts sending EDP, CDP or SONMP frame on this interface. Informations collected through EDP/CDP/FDP/SONMP are integrated with other informations and can be queried with lldpctl or through SNMP.

With the help of lldpd, you can get a map of your network. You may also want to look at Wiremaps which is a web application that helps you to see what is connected to where. 


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
