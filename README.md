miTLS
=====

miTLS is a verified reference implementation of the Internet Standard
for Transport Layer Security (TLS 1.2), as described in RFC 5246.

In addition to the verified protocol implementation (in ./src/tls),
it includes command-line tools that use this library to illustrate
sample applications over TLS (in ./apps/) and to test the conformance
and security of other implementations of the protocol (in ./flex/).
Notably, the FlexApps tool (in ./flex/FlexApps/) supports various
scenarios scripted over TLS messages, acting as a TLS client, a TLS
server, or a TLS relay.

See https://mitls.org for additional information, including research
papers that explain our code, its verification, and its usage.


1. Compilation
--------------

First, please check you have all prerequisites, as detailed in 
Section 3 below.

To compile, usually running "make" from the top level directory or
building the ./VS/miTLS.sln from Visual Studio is enough.

For each command line tool, the resulting executable is placed in a
separate `bin' directory (e.g. "./apps/echo/bin/Release/echo.exe").
Each command line tool has a "--help" option that displays all the
available command line options and their default values.

The following make targets are available:

- build (default)
    compiles miTLS and all its command line tools.

- build-debug
    compiles miTLS and all its command line tools in debug mode.

- clean
    remove object files

The internal miTLS test suite is currently not released, and thus not
available as a make target.


2. Verification
---------------

Refinement type checking of the verified code base is driven by the
Makefile in ./src/tls; this file has a "tc7" target for each file to be
type checked. Type checking requires F7 and Z3. Note that, unfortunately, 
the latest version of F7 we use is currently not released.

Each F# implementation file (with .fs extension) may use compilation
flags to control what is passed to F7 vs F#:

- ideal: enables ideal cryptographic functionalities in the code.
  (e.g. the ones performing table lookups)

- verify: enables assumptions of events in the code.

Both compilation flags are disabled when compiling the concrete code,
and enabled during type checking.

Independently, the file ./src/tls/interactive/easycrypt/KEM.ec
provides a machine-checked proof in EasyCrypt 1.0 that the master KEM of
TLS 1.2 is secure (Theorem 1 in http://eprint.iacr.org/2014/182).


3. Prerequisites and Dependencies
---------------------------------

In the following, the prerequisites for each supported platform are
given; miTLS also depends on third party software, listed below, which
must be independently obtained before compiling or running miTLS.


3.1 F# COMPILATION

In general, you need a running F# installation (see http://fsharp.org/
on how to get the most recent version of F# for your platform),
and the 'make' build utility: 

* Microsoft Windows. To get F#, you can either use Visual Studio 2013,  
  or install all of the following:
  
  - .NET version 4.5 or above
  - Visual F# 3.1 or above
  
  You need to install Cygwin to get make. 

* Linux, Mac OS X, and other variants of Unix. Use the Mono framework,
  version 3.4.0 or above and F# version 3.1 or above. Follow the
  instructions from
  http://www.mono-project.com/download/#download-lin and http://fsharp.org/use/linux/ or
  http://www.mono-project.com/download/#download-mac and http://fsharp.org/use/mac/.
  (On Mac, homebrew formulas for both mono and fsharp seem not to work and
  cannot be used to build miTLS or flexTLS.)

  make will already be on your machine. 

3.2 THIRD PARTY CODE INCLUDED IN THIS DISTRIBUTION.

- OpenSSL (https://www.openssl.org):

    ./3rdparty/licenses/openSSL.txt
    ./3rdparty/libeay32-x86.dll
    ./3rdparty/libeay32-x64.dll

- Python (https://www.python.org/downloads/):

    ./3rdparty/licenses/python.txt
    ./3rdparty/pyruntime/ucs2-win/Python.Runtime.dll
    ./3rdparty/pyruntime/ucs4-unix/Python.Runtime.dll

Finally, ./FlexApps/Serialization.fs embeds third-party source code
from 15below Ltd (https://github.com/15below/FifteenBelow.Json); their
license appears in 3rdparty/licenses/FifteenBelow.Json.txt.


3.3. EXTERNAL DEPENDENCIES. They are automatically installed as nuget
packages within Visual Studio: building the solution downloads and
installs the packages listed below. Alternatively, install nuget and
then run "nuget restore" in ./VS/ to install these packages.

- BouncyCastle 1.7  https://www.nuget.org/packages/BouncyCastle/
- FsharpPowerPack 3 https://www.nuget.org/packages/FSPowerPack.Community
- Json.NET 6.0.8    https://www.nuget.org/packages/Newtonsoft.Json
- NLog 3.2.0        https://www.nuget.org/packages/NLog/3.2.0
- SQLite3 1.0.96.0  https://www.nuget.org/packages/System.Data.SQLite


4. Certificates and Parameters
------------------------------

To use X.509 certificates, notably for testing, miTLS relies on a
certificate store. On Windows, the Windows store handles management
of those. For other Unix platforms, the Mono store is used.

The following are guidelines on how to import certificates into the
store, as required to run TLS scenarios involving certificates,
according to your platform.

Diffie-Hellman ciphersuites additionally require default parameters
to be loaded from a file. A sample default-dh.pem file with default
parameters is provided in the data/dh directory.

### 4.a. Microsoft Windows

Add a CA certificate to the store by using the certutil command

  certutil -f -user -addstore Root ca.crt

Add a personal certificate to the store by using the certutil command

  certutil -f -user -p '' -v -importpfx certificate.p12

Delete a CA certificate from the store by using the certutil command

  certutil -user -delstore Root <NAME>

Delete a certificate from the store by using the certutil command

  certutil -user -delstore My <NAME>


For convenience, a template install is provided with this release.
To install the PKI, go to miTLS-0.9.0/tests and run "make pki.built"
using Cygwin to generate and install certificates.
If the installation of the certificates works, you should be prompted
with a message to choose whether or not to accept them.
You will need to install the openssl-perl package available on Cygwin.

### 4.b. Linux, MacOS X and other Un*ces

Add a CA certificate to the store by using the certmgr command

  umask 077; certmgr -add -c Trust ca.crt

Add a personal certificate to the store by using the certmgr command

  umask 077; ( set -e; \
    certmgr -add       -c My <NAME>.crt;      \
    certmgr -importKey -c -p '' My <NAME>.p12 \
  )

Delete a CA certificate from the store by using the certmgr command

  certmgr -del -c Trust <NAME>

Delete a certificate from the store by using the certmgr command

  certmgr -del -c My <NAME>


For convenience, a template install is provided with this release.
To install the PKI, go to miTLS-0.9.0/test and run "make pki.built" to
generate and install certificates.
On Fedora, you will need to install the openssl-perl package before
doing this.


5. FlexTLS
----------

The FlexTLS library and the FlexApps console application are
built upon miTLS, for testing implementations of the TLS protocol.

The Visual Studio solution can be found in the miTLS-0.9.0/VS folder.
The user should set the Startup project to be FlexApps. The main
product of compilation is the "FlexApps.exe" executable. It can be
found in the flex/FlexApps/bin/Release.

The FlexApps project stores the scenarios; Application.fs implements
the command line interface and it is the file where the calls to those
scenarios can be managed. This will run by default if built in Release
mode. Script.fs is the default scenario that will be executed if the
solution is built in Debug mode. It is the perfect location to build
and test your own scenarios.

A sample default-dh.pem file with default parameters and a
dhparams-db.bin template database are available in the
miTLS-0.9.0/data/dh directory and should be copied into the
flex/FlexApps/bin/Release/ directory. Note that the database has to
be in your current working directory. We do recommend that you run
FlexApps.exe from the Release directory.

You can run the tool in the client role and test a scenario using the
following command :

./FlexApps.exe -s <scenario name> --connect <address>:<port number>

You can also run as a server using the following command :

./FlexApps.exe -s <scenario name> --accept 127.0.0.1:<port> --server-cert mitls

Several scenarios are available including:
- fh :
  "full handshake", it will run a standard, correct full TLS handshake

- smacktls :
  Several deviant traces, used to detect implementation issues

- script :
  Your scenario written in the "run" function of the script.fs file

For more informations you can use the --help command line option.


6. Contact
----------

Please contact us if you have difficulties in building or running the tool. 
The best way is by raising an Issue on GitHub. 
Alternatively, you may contact us by e-mail.

Benjamin Beurdouche
benjamin.beurdouche@inria.fr

Karthikeyan Bhargavan
karthikeyan.bhargavan@inria.fr

Antoine Delignat-Lavaud
antoine.delignat-lavaud@inria.fr

Cedric Fournet
fournet@microsoft.com

Samin Ishtiaq
samin.ishtiaq@microsoft.com

Markulf Kohlweiss
markulf@microsoft.com

Santiago Zanella-Béguelin
santiago@microsoft.com
