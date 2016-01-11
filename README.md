# PowerShell Async IPScanner

Powerful asynchronous IP-Scanner which returns a custom PowerShell-Object with basic informations about the scanned IP-Range include IP-Address, Hostname (with FQDN) and Status.

## Description

I built this powerful asynchronous IP-Scanner, because every script i found on the Internet was very slow. Most of them do there job, but ping every IP/Host in sequence and/or no one could ping more than /24. This is Ok if you have a few host, but if you want to scan a large IP-Range, you waste a lot of time.

In this script i work with the PowerShell RunspacePool , because PSJobs are to slow. 

This Script can scan every IP-Range you want. To do this, just enter a Start IP-Address and an End IP-Address. You don't need a specific subnetmask (for example 172.16.1.47 to 172.16.2.5 would work).

You can modify the threads at the same time, the wait time if all threads are busy and the tries for each IP in the parameter (use Get-Help for more details).
  
If all IPs are finished scanning, the script returns a custom PowerShell object which include IP-Address, Hostname (with FQDN) and the Status (Up or Down). You can easily process this PSObject in a foreach-loop like every other object in PowerShell.

## Syntax

```powershell
.\ScanNetworkAsync.ps1 [-StartIPAddress] <IPAddress> [-EndIPAddress] <IPAddress> [[-Threads] <Int32>] [[-Tries] <Int32>] [[-IncludeInactive]] [[-ResolveDNS]] [[-GetMAC]] [<CommonParameters>] 
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

## Output

```powershell
IPv4Address     Hostname                  MAC                   Status
-----------     --------                  ---                   ------
172.16.0.1      FRITZ.BOX                 AA-BB-CC-DD-EE-FF     Up
172.16.0.21     ANDROID-01.FRITZ.BOX      AA-AA-BB-BB-DD-EE     Up
172.16.0.22     ANDROID-02.FRITZ.BOX                            Down
172.16.0.23     VM-2012R2-01.FRITZ.BOX    00-11-22-33-44-55     Up
172.16.0.28     VPC-TEST-01.FRITZ.BOX     AA-00-BB-11-CC-22     Up
 ```