# PowerShell | IPv4 network scanner

Powerful asynchronus IPv4 network scanner for PowerShell.

## Description

This powerful asynchronus IPv4 network scanner for PowerShell allows you to scan every IPv4 range you want (172.16.1.47 to 172.16.2.5 would work). But there is also the possibility to scan an entire subnet based on an IPv4 address withing the subnet and a the subnetmask/CIDR.

The default result will contain the the IPv4 address, status (Up or Down) and the hostname. Other values can be displayed via parameter (Try Get-Help for more details).

![Screenshot](Documentation/Images/IPv4NetworkScan.png?raw=true "IPv4NetworkScan")

To reach the best possible performance, this script uses a [RunspacePool](https://msdn.microsoft.com/en-US/library/system.management.automation.runspaces.runspacepool(v=vs.85).aspx). As you can see in the following screenshot, the individual tasks are distributed across all cpu cores:

![Screenshot](Documentation/Images/IPv4NetworkScan_CPUusage.png?raw=true "CPU usage")

If you are looking for a module containing this script as function... you can find it [here](https://github.com/BornToBeRoot/PowerShell)!

Maybe you're also interested in my asynchronus [IPv4 Port Scanner](https://github.com/BornToBeRoot/PowerShell_IPv4PortScanner).

## Syntax

```powershell
.\IPv4NetworkScan.ps1 [-StartIPv4Address] <IPAddress> [-EndIPv4Address] <IPAddress> [[-Tries] <Int32>] [[-Threads] <Int32>] [[-DisableDNSResolving]] [[-EnableMACResolving]] [[-ExtendedInformations]] [[-IncludeInactive]] [<CommonParameters>]

.\IPv4NetworkScan.ps1 [-IPv4Address] <IPAddress> [-Mask] <String> [[-Tries] <Int32>] [[-Threads] <Int32>] [[-DisableDNSResolving]] [[-EnableMACResolving]] [[-ExtendedInformations]] [[-IncludeInactive]] [<CommonParameters>]

.\IPv4NetworkScan.ps1 [-IPv4Address] <IPAddress> [-CIDR] <Int32> [[-Tries] <Int32>] [[-Threads] <Int32>] [[-DisableDNSResolving]] [[-EnableMACResolving]] [[-ExtendedInformations]] [[-IncludeInactive]] [<CommonParameters>]
```

## Example 1

```powershell
PS> .\IPv4NetworkScan.ps1 -StartIPv4Address 192.168.178.0 -EndIPv4Address 192.168.178.20

IPv4Address   Status Hostname
-----------   ------ --------
192.168.178.1 Up     fritz.box
```

## Example 2

```powershell
PS> .\IPv4NetworkScan.ps1 -IPv4Address 192.168.178.0 -Mask 255.255.255.0 -DisableDNSResolving

IPv4Address    Status
-----------    ------
192.168.178.1  Up
192.168.178.22 Up
```

## Example 3

```powershell
PS> .\IPv4NetworkScan.ps1 -IPv4Address 192.168.178.0 -CIDR 25 -EnableMACResolving

IPv4Address    Status Hostname           MAC               Vendor
-----------    ------ --------           ---               ------
192.168.178.1  Up     fritz.box          XX-XX-XX-XX-XX-XX AVM Audiovisuelles Marketing und Computersysteme GmbH
192.168.178.22 Up     XXXXX-PC.fritz.box XX-XX-XX-XX-XX-XX ASRock Incorporation
```

