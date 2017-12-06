%define name tcf-agent
%define version 1.6.0
%define release 1.%(bin/get-os-tag)
%define make_options CONF=Release PATH_Plugins=/etc/tcf/plugins

Name: %{name}
Summary: Target Communication Framework agent
Version: %{version}
Release: %{release}
Vendor: eclipse.org
Source: http://git.eclipse.org/c/tcf/org.eclipse.tcf.agent.git
URL: http://wiki.eclipse.org/TCF
Group: Development/Tools/Other
BuildRoot: %{_tmppath}/%{name}-buildroot
License: EPL
Requires: openssl, e2fsprogs

%description
Target Communication Framework is universal, extensible, simple,
lightweight, vendor agnostic framework for tools and targets to
communicate for purpose of debugging, profiling, code patching and
other device software development needs. tcf-agent is a daemon,
which provides TCF services that can be used by local and remote clients.

%prep
rm -rf $RPM_BUILD_ROOT

%setup

%build
make %{make_options} all

%install
make %{make_options} install INSTALLROOT=$RPM_BUILD_ROOT SBIN=%{_sbindir} INCLUDE=%{_includedir}

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%post
if [ ! -r /etc/tcf/ssl/local.priv -o ! -r /etc/tcf/ssl/local.cert ] ; then
  %{_sbindir}/tcf-agent -c
fi
chkconfig --add %{name}
/sbin/service %{name} start > /dev/null 2>&1 || :

%postun
if [ $1 -ge 1 ] ; then
  /sbin/service %{name} condrestart > /dev/null 2>&1 || :
fi

%preun
if [ "$1" = 0 ] ; then
  /sbin/service %{name} stop > /dev/null 2>&1 || :
  chkconfig --del %{name}
fi

%files
%defattr(-,root,root,0755)
%config /etc/init.d/%{name}
%{_sbindir}/tcf-agent
%{_sbindir}/tcf-client
%{_includedir}/tcf

%changelog
* Wed Jun 01 2017 Eugene Tarassov <eugene.tarassov@xilinx.com> 1.5.0
- Eclipse 4.7.0 Oxygen release
* Wed Jul 05 2016 Eugene Tarassov <eugene.tarassov@xilinx.com> 1.4.0
- Eclipse 4.6.0 Neon release
* Wed Jun 24 2015 Eugene Tarassov <eugene.tarassov@xilinx.com> 1.3.0
- Eclipse 4.5.0 Mars release
* Wed Jun 25 2014 Eugene Tarassov <eugene.tarassov@xilinx.com> 1.2.0
- Eclipse 4.4.0 Luna release
* Wed Jun 12 2013 Eugene Tarassov <eugene.tarassov@xilinx.com> 1.1.0
- Eclipse 4.3.0 Kepler release
* Wed Jun 06 2012 Eugene Tarassov <eugene.tarassov@xilinx.com> 1.0.0
- Eclipse 3.8.0, 4.2.0 Juno release
* Mon May 16 2011 Eugene Tarassov <eugene.tarassov@windriver.com> 0.4.0
- Eclipse 3.7.0 Indigo release
* Thu Jun 03 2010 Eugene Tarassov <eugene.tarassov@windriver.com> 0.3.0
- Eclipse 3.6.0 Helios release
* Thu Mar 12 2009 Eugene Tarassov <eugene.tarassov@windriver.com> 0.0.1
- first release
