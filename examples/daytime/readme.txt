Readme for TCF Agent Daytime Example
------------------------------

The Agent Daytime Example shows how a TCF agent can be customized and extended
with a user-defined service.

The example provides code to build the agent with a custom set of services,
including user-defined "Daytime" service. The service is registered via
the main/services-ext.h extension point.

The example is mainly meant for developer's educational use, the Daytime
service is not meant to be of any other value. There is also a TCF Java 
counterpart of this example, providing a Service Proxy: See 
"org.eclipse.tm.tcf.examples.daytime" for details on extending TCF Java 
binding for the Daytime service.

The example includes:
1. Makefile to build the customized agent.
2. Implementation of DayTime service: tcrf/services/daytime.[hc]
3. Agent configuration header file: tcf/config.h

CDT can be used to edit and build the example project.
Supported agent execution environments: Msys, CygWin, Linux.


Building and Running the Example
----------------------------
make NO_SSL=1 NO_UUID=1
obj/*/*/Debug/agent -L- &
../agent/obj/*/*/Debug/client <<<EOF
connect TCP::1534
services
tcf Daytime getTimeOfDay "de"
EOF


Building a Minimal-Footprint Agent
----------------------------
make NO_SSL=1 NO_UUID=1 CONF=Release CFLAGS="-DENABLE_Trace=0 -DENABLE_Discovery=0 -DSERVICE_FileSystem=0 -DSERVICE_SysMonitor=0"
ls -l obj/GNU/Linux/x86_64/Release/
total 428
-rwxrwxr-x. 1 mober users 123504 Nov 14 12:01 agent
-rw-rw-r--. 1 mober users 298280 Nov 14 12:01 libtcf.a

