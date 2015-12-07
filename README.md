# PowerShell-Async-IPScanner

## Description
Scan Network Async and return PSObject (IPv4Address, Hostname, FQDN, Status)

Currently the first 3 quads of the IP-Address must be the same... you can only scan a range of /24.

## Syntax
ScanNetworkAsync.ps1 [-StartIP] <string> [-EndIP] <string> [[-MaxThreads] <int>] [[-SleepTimer] <int>]

## Example
ScanNetworkAsync.ps1 -StartIP 192.168.1.1 -EndIP 192.168.168.1.100 -MaxThreads 15 -SleepTimer 500
