# PowerShell Async IPScanner

Powerful asynchronous IP-Scanner which returns a custom PowerShell-Object with basic informations about the scanned IP-Range include IP-Address, Hostname (with FQDN), MAC and Status.

## Description

I built this powerful asynchronous IP-Scanner, because every script i found on the Internet was very slow. Most of them do there job, but ping every IP/Host in sequence and/or no one could ping more than /24. This is Ok if you have a few host, but if you want to scan a large IP-Range, you waste a lot of time.

In this script i work with the PowerShell RunspacePool , because PSJobs are to slow. 

This Script can scan every IP-Range you want. To do this, just enter a Start IP-Address and an End IP-Address. You don't need a specific subnetmask (for example 172.16.1.47 to 172.16.2.5 would work).

You can modify the threads at the same time, the wait time if all threads are busy and the tries for each IP in the parameter (use Get-Help for more details).
  
If all IPs are finished scanning, the script returns a custom PowerShell object which include IP-Address, Hostname (with FQDN) and the Status (Up or Down). If you use the parameter "-GetMAC" it also would return the MAC (with Vendor) and with the parameter "-ExtendedInformations" you can get the IPv6Address (if available), BufferSize, ResponseTime (ms) and TTL. You can easily process this PSObject in a foreach-loop like every other object in PowerShell.

Maybe you also interested in my [asynchronous Port-Scanner](https://github.com/BornToBeRoot/PowerShell_Async-PortScanner)

![Screenshot of Working Scanner and Result](https://github.com/BornToBeRoot/PowerShell_Async-IPScanner/blob/master/Images/Working_and_Result.png?raw=true)

## Syntax

```powershell
.\ScanNetworkAsync.ps1 [-StartIPAddress] <IPAddress> [-EndIPAddress] <IPAddress> [[-Threads] <Int32>] [[-Tries] <Int32>] [[-IncludeInactive]] [[-ResolveDNS]] [[-GetMAC]] [[-ExtendedInformations]] [[-UpdateListFromIEEE] [<CommonParameters>] 
```

## Example

Simple IP-Range Scan

```powershell
.\ScanNetworkAsync.ps1 -StartIPAddress 192.168.1.1 -EndIPAddress 192.168.1.200 
```

Include inactive devices

```powershell 
.\ScanNetworkAsync.ps1 -StartIPAddress 172.16.0.1 -EndIPAddress 172.16.1.254 -IncludeInactive
```

Get MAC-Addresses (Only work if you are in the same Subnet)

```powershell
.\ScanNetworkAsync.ps1 -StartIPAddress 192.168.10.1 -EndIPAddress 192.168.10.25 -GetMAC
```

Disable DNS resolving

```powershell
.\ScanNetworkAsync.ps1 -StartIPAddress 192.168.2.100 -EndIPAddress 192.168.2.254 -ResolveDNS:$false
```

Get extended informations (and MAC)

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
With "-GetMAC" and "-ExtendedInformations"

```PowerShell
IPv4Address     Hostname                  MAC                   Vendor     IPv6Address                         BufferSize ResponseTime TTL  Status
-----------     --------                  ---                   ------     -----------                         ---------- ------------ ---  ------
172.16.0.1      FRITZ.BOX                 AA-BB-CC-DD-EE-FF     AVM        XXXX:XX:XXX:XXXX:XXX:XXXX:XXXX:XXXX         32            0  64  Up
172.16.0.21     ANDROID-01.FRITZ.BOX      AA-AA-BB-BB-DD-EE     Cisco                                                  32            2  64  Up
172.16.0.22     ANDROID-02.FRITZ.BOX                                                                                                        Down
172.16.0.23     VM-2012R2-01.FRITZ.BOX    00-11-22-33-44-55     Netgear    XXXX:XX:XXX:XXXX:XXX:XXXX:XXXX:XXXX         32            2  64  Up
172.16.0.28     VPC-TEST-01.FRITZ.BOX     AA-00-BB-11-CC-22     Netgear    XXXX:XX:XXX:XXXX:XXX:XXXX:XXXX:XXXX         32            1  64  Up
```
