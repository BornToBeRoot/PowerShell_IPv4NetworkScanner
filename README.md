# PowerShell Async IPScanner

Powerful asynchronous IP-Scanner which returns a custom PowerShell-Object with basic informations about the scanned IP-Range include IP-Address, Hostname (with FQDN), MAC and Status.

## Description

I built this powerful asynchronous IP-Scanner, because every script i found on the Internet was very slow. Most of them do there job, but ping every IP/Host in sequence and/or no one could ping more than a Subnet with more than /24 hosts.

This Script can scan every IP-Range you want. To do this, just enter a Start IP-Address and an End IP-Address. You don't need a specific subnetmask (for example 172.16.1.47 to 172.16.2.5 would work).

I use the PowerShell-RunspacePool in this script, to run the ICMP requests, DNS resolve etc. asynchron.

You can modify the threads at the same time, the wait time if all threads are busy and the tries for each IP in the parameter (use Get-Help for more details).
  
If all IPs are finished with scanning, the script returns a custom PowerShell-Object which include IP-Address, Hostname (with FQDN) and the Status (Up or Down). If you use the parameter "-GetMAC" it also would return the MAC (with Vendor) and with the parameter "-ExtendedInformations" you can get the IPv6Address (if available), BufferSize, ResponseTime (ms) and TTL. You can easily process this PSObject in a foreach-loop like every other object in PowerShell.

Maybe you are also interested in my [asynchronous Port-Scanner](https://github.com/BornToBeRoot/PowerShell_Async-PortScanner)

![Screenshot of Working Scanner and Result](https://github.com/BornToBeRoot/PowerShell_Async-IPScanner/blob/master/Documentation/ScanNetworkAsync_Result.png?raw=true)

## Syntax

```powershell
.\ScanNetworkAsync.ps1 [-StartIPAddress] <IPAddress> [-EndIPAddress] <IPAddress> [[-Threads] <Int32>] [[-Tries] <Int32>] [[-IncludeInactive]] [[-ResolveDNS]] [[-GetMAC]] [[-ExtendedInformations]] [[-UpdateListFromIEEE] [<CommonParameters>] 
```

## Example

Simple IP-Range Scan

```powershell
.\ScanNetworkAsync.ps1 -StartIPAddress 192.168.1.1 -EndIPAddress 192.168.1.200 
```

You may want to update the official "Registration Authority" from IEEE... Just add the parameter "-UpdateListFromIEEE".

```powershell
.\ScanNetworkAsync.ps1 -StartIPAddress 192.168.1.1 -EndIPAddress 192.168.1.200 -UpdateListFromIEEE
```

Get extended informations and MAC-Address with vendor

```powershell
.\ScanNetworkAsync.ps1 -StartIPAddress 172.16.0.1 -EndIPAddress 172.16.1.254 -GetMAC -ExtendedInformations
```

## Output

```powershell
IPv4Address     Hostname                  Status
-----------     --------                  ------
172.16.0.1      FRITZ.BOX                 Up
172.16.0.21     ANDROID-01.FRITZ.BOX      Up
172.16.0.22     ANDROID-02.FRITZ.BOX      Down
172.16.0.23     VM-2012R2-01.FRITZ.BOX    Up
172.16.0.28     VPC-TEST-01.FRITZ.BOX     Up
 ```
With "-GetMAC"

```powershell
IPv4Address     Hostname                  MAC                   Vendor     Status
-----------     --------                  ---                   ------     ------
172.16.0.1      FRITZ.BOX                 AA-BB-CC-DD-EE-FF     AVM        Up
172.16.0.21     ANDROID-01.FRITZ.BOX      AA-AA-BB-BB-DD-EE     Cisco      Up
172.16.0.22     ANDROID-02.FRITZ.BOX                                       Down
172.16.0.23     VM-2012R2-01.FRITZ.BOX    00-11-22-33-44-55     Netgear    Up
172.16.0.28     VPC-TEST-01.FRITZ.BOX     AA-00-BB-11-CC-22     Netgear    Up
```
With "-GetMAC", "-ExtendedInformations" and "-IncludeInactive"

```PowerShell
IPv4Address     Hostname                  MAC                   Vendor     BufferSize ResponseTime TTL  Status
-----------     --------                  ---                   ------     ---------- ------------ ---  ------
172.16.0.1      FRITZ.BOX                 AA-BB-CC-DD-EE-FF     AVM                32            0  64  Up
172.16.0.21     ANDROID-01.FRITZ.BOX      AA-AA-BB-BB-DD-EE     Cisco              32            2  64  Up
172.16.0.22     ANDROID-02.FRITZ.BOX                                                                    Down
172.16.0.23     VM-2012R2-01.FRITZ.BOX    00-11-22-33-44-55     Netgear            32            2  64  Up
172.16.0.28     VPC-TEST-01.FRITZ.BOX     AA-00-BB-11-CC-22     Netgear            32            1  64  Up
```
