# IPv4-Scanner

Powerful asynchronus IPv4-Scanner for PowerShell.

## Description

This powerful asynchronus IPv4-Scanner allows you to scan every IPv4-Range you want (172.16.1.47 to 172.16.2.5 would work). But there is also the possibility to scan an entire subnet based on an IPv4-Address withing the subnet and a the subnetmask/CIDR.

The default result will contain the the IPv4-Address, Status (Up or Down) and the Hostname. Other values can be displayed via parameter (Try Get-Help for more details).

![Screenshot of Working Scanner and Result](https://github.com/BornToBeRoot/PowerShell_IPv4-Scanner/blob/master/Documentation/New-IPv4Scan.png?raw=true "New-IPv4Scan")

Maybe you are also interested in my [asynchronous Port-Scanner](https://github.com/BornToBeRoot/PowerShell_Async-PortScanner)

## Syntax

```powershell
.\New-IPv4Scan.ps1 [-StartIPv4Address] <IPAddress> [-EndIPv4Address] <IPAddress> [[-Tries] <Int32>] [[-Threads] <Int32>] [[-DisableDNSResolving]] [[-EnableMACResolving]] [[-ExtendedInformations]] [[-IncludeInactive]] [[-UpdateList]] [<CommonParameters>]

.\New-IPv4Scan.ps1 [-IPv4Address] <IPAddress> [-Mask] <String> [[-Tries] <Int32>] [[-Threads] <Int32>] [[-DisableDNSResolving]] [[-EnableMACResolving]] [[-ExtendedInformations]] [[-IncludeInactive]] [[-UpdateList]] [<CommonParameters>]

.\New-IPv4Scan.ps1 [-IPv4Address] <IPAddress> [-CIDR] <Int32> [[-Tries] <Int32>] [[-Threads] <Int32>] [[-DisableDNSResolving]] [[-EnableMACResolving]] [[-ExtendedInformations]] [[-IncludeInactive]] [[-UpdateList]] [<CommonParameters>]
```

## Example

```powershell
PS> .\New-IPv4Scan.ps1 -StartIPv4Address 192.168.178.0 -EndIPv4Address 192.168.178.20

IPv4Address   Status Hostname
-----------   ------ --------
192.168.178.1 Up     fritz.box
```

```powershell
PS> .\New-IPv4Scan.ps1 -IPv4Address 192.168.178.0 -Mask 255.255.255.0 -DisableDNSResolving

IPv4Address    Status
-----------    ------
192.168.178.1  Up
192.168.178.22 Up
```

```powershell
PS> .\New-IPv4Scan.ps1 -IPv4Address 192.168.178.0 -CIDR 25 -EnableMACResolving

IPv4Address    Status Hostname           MAC               Vendor
-----------    ------ --------           ---               ------
192.168.178.1  Up     fritz.box          XX-XX-XX-XX-XX-XX AVM Audiovisuelles Marketing und Computersysteme GmbH
192.168.178.22 Up     XXXXX-PC.fritz.box XX-XX-XX-XX-XX-XX ASRock Incorporation
```
