# PowerShell Async IPScanner

## Description
Network Scanner for PowerShell to scan IP-Range async
    
Returns an PowerShell Object with basic informations about the Network like IP, Hostname, FQDN and Status
    
The first three quads of the IP-Range must be the same (like 192.168.1.XX - 192.168.1.XX).

## Syntax
ScanNetworkAsync.ps1 [-StartIP] $string [-EndIP] $string [[-MaxThreads] $int] [[-SleepTimer] $int]

## Example
ScanNetworkAsync.ps1 -StartIP 192.168.1.1 -EndIP 192.168.168.1.100 -MaxThreads 15 -SleepTimer 500
