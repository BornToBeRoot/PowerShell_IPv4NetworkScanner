# PowerShell Async IPScanner

Async Network Scanner which returns a custom PowerShell object with basic informations about the scanned IP-Range include IP-Address, Hostname (with FQDN) and Status.

## Description

I built this powerful asynchronous IP-Scanner, because every script i found on the Internet was very slow. Most of them do there job, but ping every IP/Host in sequence and no one of them could ping more than /24. This is Ok if you have a few host, but if you want to scan a large IP-Range, you need a lot of hot coffee :)

This Script can scan every IP-Range you want. To do this, just enter a Start IP and an End IP. This Script don't need a subnetmask (for example 172.16.1.47 to 172.16.2.5 would work).

You can modify the threads at the same time, the wait time if all threads are busy and the tries for each IP in the parameter (use Get-Help for more details).
  
If all IPs are finished scanning, the script returns a custom PowerShell object which include IP-Address, Hostname (with FQDN) and the Status (Up or Down). You can easily process this PSObject in a foreach-loop like every other object in PowerShell.
    
If you found a bug or have some ideas to improve this script... Let me know. You find my Github profile in the links below.

Last but not least: Have fun with it!


## Syntax

```powershell
ScanNetworkAsync.ps1 [-StartIPAddress] <IPAddress> [-EndIPAddress] <IPAddress> [[-Threads] <Int32>] [[-Wait] <Int32>] [[-Tries] <Int32>] [[-ActiveOnly]] [[-AlwaysDNS]] [<CommonParameters>]
```

## Example

Simple IP-Range Scan
```powershell
 .\ScanNetworkAsync.ps1 -StartIPAddress 192.168.1.1 -EndIPAddress 192.168.1.200
```
More threads, DNS from inaktiv devices
```powershell 
 .\ScanNetworkAsync.ps1 -StartIPAddress 172.16.0.1 -EndIPAddress 172.16.1.254 -Threads 50 -Wait 250 -Tries 4 -AlwaysDNS
 ```
 
 Get only active devices
 ```powershell
 .\ScanNetworkAsync.ps1 -StartIPAddress 172.16.0.1 -EndIPAddress 172.16.1.254 -ActiveOnly
 ```
 
## ToDo

- Improve perfomance