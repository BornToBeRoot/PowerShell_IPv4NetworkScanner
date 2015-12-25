# Old Version with PSJobs

##################################################################################################################
### Help
##################################################################################################################

<#
    .SYNOPSIS
    Async Network Scanner which returns a custom PowerShell object with basic informations about the scanned 
    IP-Range include IP-Address, Hostname (with FQDN) and Status.

    .DESCRIPTION
    I built this powerful asynchronous IP-Scanner, because every script i found on the Internet was very slow. 
    Most of them do there job, but ping every IP/Host in sequence and no one of them could ping more than /24. 
    This is Ok if you have a few host, but if you want to scan a large IP-Range, you need a lot of hot coffee :)

    This Script can scan every IP-Range you want. To do this, just enter a Start IP and an End IP. This Script 
    don't need a subnetmask (for example 172.16.1.47 to 172.16.2.5 would work).
    
    You can modify the threads at the same time, the wait time if all threads are busy and the tries for each 
    IP in the parameter (use Get-Help for more details).
    
    If all IPs are finished scanning, the script returns a custom PowerShell object which include IP-Address, 
    Hostname (with FQDN) and the Status (Up or Down). You can easily process this PSObject in a foreach-loop 
    like every other object in PowerShell.
    
    If you found a bug or have some ideas to improve this script... Let me know. You find my Github profile in 
    the links below.

    Last but not least: Have fun with it!
                
    .EXAMPLE
    ScanNetworkAsync.ps1 -StartIPAddress 192.168.1.1 -EndIPAddress 192.168.1.200
    
    .EXAMPLE
    ScanNetworkAsync.ps1 -StartIPAddress 172.16.0.1 -EndIPAddress 172.16.1.254 -Threads 50 -Wait 250 -Tries 4

    .LINK
    Github profile:     https://github.com/BornToBeRoot/PowerShell-Async-IPScanner
#>

##################################################################################################################
### Parameter and default values
##################################################################################################################

[CmdletBinding()]
param(
	[Parameter(
		Position=0,
		Mandatory=$true,
		HelpMessage='Start IP like 172.16.0.1')]
	[IPAddress]$StartIPAddress,
	
	[Parameter(
		Position=1,
		Mandatory=$true,
		HelpMessage='End IP like 172.16.1.254')]
	[IPAddress]$EndIPAddress,

	[Parameter(
		Position=2,
		Mandatory=$false,
		HelpMessage='Maximum threads at the same time (Default 20)')]
	[Int32]$Threads=20,
	
	[Parameter(
		Position=3,
		Mandatory=$false,
		HelpMessage='Wait time in Milliseconds if all threads are busy (Default 500)')]
	[Int32]$Wait=500,

	[Parameter(
		Position=4,
		Mandatory=$false,
		HelpMessage='Maximum number of Test-Connection checks for each IP  (Default 2)')]
	[Int32]$Tries=2,

    [Parameter(
        Position=5,
        Mandatory=$false,
        HelpMessage='Show only active devices in result')]
    [switch]$ActiveOnly,

    [Parameter(
        Position=6,
        Mandatory=$false,
        HelpMessage='Resolve DNS for non-active devices (some performance issues)')]
    [switch]$AlwaysDNS
)

##################################################################################################################
### Begin:  Validate IP-range, include functions
##################################################################################################################

begin{
	### Something maybe usefull :)
    $StartTime = Get-Date
    $ScriptFileName = $MyInvocation.MyCommand.Name      
      
    ###### # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
    ### You can find this two functions in the following script:      https://gallery.technet.microsoft.com/scriptcenter/List-the-IP-addresses-in-a-60c5bb6b#content 
    ### Published under the MS-LPL license you can fin here:          https://www.openhub.net/licenses/mslpl
    function IP-toInt64 () { 
        param ($IPAddr) 
 
        $Octets = $IPAddr.split(".") 
        return [long]([long]$Octets[0]*16777216 +[long]$Octets[1]*65536 +[long]$Octets[2]*256 +[long]$Octets[3]) 
    } 
    
    function Int64-toIP() { 
        param ([long]$Int) 

        return (([System.Math]::Truncate($Int/16777216)).ToString() + "." + ([System.Math]::Truncate(($Int%16777216)/65536)).tostring() + "." + ([System.Math]::Truncate(($int%65536)/256)).ToString() + "." + ([System.Math]::Truncate($int%256)).ToString())
    }
    ###### # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 

    $StartIPAddress_Int64 = IP-toInt64 -IPAddr $StartIPAddress.ToString()
    $EndIPAddress_Int64 = IP-toInt64 -IPAddr $EndIPAddress.ToString()
    $IPRange_Int64 = ($EndIPAddress_Int64 - $StartIPAddress_Int64)

    ### Check if Start IP is greater than End IP
    if($StartIPAddress_Int64 -gt $EndIPAddress_Int64)
    {
        Write-Host "Check your input! Invalid IP-range... (-EndIPAddress can't be lower than -StartIPAddress)" -ForegroundColor Red
        exit
    }

	### Some user-output...	
    Write-Host "Script ($ScriptFileName) started at $StartTime" -ForegroundColor Green
    Write-Host "`n----------------------------------------------------------------------------------------------------`n"
    Write-Host "IP-Range:`t`t$StartIPAddress - $EndIPAddress"
    Write-Host "Threads:`t`t$Threads"
    Write-Host "Wait:`t`t`t$Wait (Milliseconds)"
    Write-Host "Tries:`t`t`t$Tries"
    Write-Host "`n----------------------------------------------------------------------------------------------------`n"      
}

##################################################################################################################
### Process: Async IP-Scan (with resolving DNS)
##################################################################################################################

Process{ 
    Write-Host "Scanning IPs...`n" -ForegroundColor Yellow
      
    for ($i = $StartIPAddress_Int64; $i -le $EndIPAddress_Int64; $i++) 
    { 
        While ($(Get-Job -state running).count -ge $Threads)
        {
            Start-Sleep -Milliseconds $Wait
        }   
              
        $IPv4Address = Int64-toIP -Int $i 

        Write-Progress -Activity "Scanning IP.." -Id 1 -status $IPv4Address -PercentComplete ((($i - $StartIPAddress_Int64) / $IPRange_Int64) * 100)
                
        $ScriptBlockCode = { 

            $IPv4Address = $args[0]
            $Tries = $args[1]
                
            if(Test-Connection -ComputerName $IPv4Address -Count $Tries -Quiet) { $Status = "Up" } else { $Status = "Down" }		
		    
            if($Status -eq "Up" -or $AlwaysDNS)
            {
                $FQDN = [String]::Empty
		        $Hostname = [String]::Empty
		
		        try {
		            $Hostname = ([System.Net.Dns]::GetHostEntry($IPv4Address).HostName).ToUpper()                       			        
	            }
		        catch { } # No DNS found
        	} 

		    $Device = New-Object -TypeName PSObject
            Add-Member -InputObject $Device -MemberType NoteProperty -Name IPv4Address -Value $IPv4Address
            Add-Member -InputObject $Device -MemberType NoteProperty -Name Hostname -Value $Hostname            
		    Add-Member -InputObject $Device -MemberType NoteProperty -Name Status -Value $Status
		
            return $Device      
        }

        Start-Job -ArgumentList $IPv4Address, $Tries -ScriptBlock $ScriptBlockCode | Out-Null          

        $RunningThreads = (Get-Job -State Running).Count

        Write-Progress -Activity "Running threads.." -Id 2 -ParentId 1 -Status "$RunningThreads of $Threads" -PercentComplete (($RunningThreads / $Threads)  * 100)
    }
        
    Write-Progress -Activity "Scan finished" -Id 1 -status $EndIPAddress -PercentComplete (100)

    ### Wait until jobs are finished, but still display progress
    while(Get-Job -State Running)
    {
       $RunningThreads = (Get-Job -State Running).Count

       Write-Progress -Activity "Waiting for threads.." -Id 2 -ParentId 1 -Status "$RunningThreads of $Threads Threads" -PercentComplete (($RunningThreads / $Threads)  * 100)

       Start-Sleep -Milliseconds $Wait 
    }
    
    Write-Host "`nScan finished!" -ForegroundColor Yellow
    
    ### Built global array, wait for jobs and remove them
    $Devices = New-Object System.Collections.ArrayList
   
    Get-Job | Receive-Job | % { $Devices.Add(($_ | Select-Object IPv4Address, Hostname, Status))} | Out-Null
   
    Get-Job | Remove-Job | Out-Null
}

##################################################################################################################
### End: user output, return custom psobject
##################################################################################################################

End {
    $DevicesUp = @($Devices | Where-Object {($_.Status -eq "Up")}).Count
    $DevicesDown = @($Devices | Where-Object {($_.Status -eq "Down") -and (-not([String]::IsNullOrEmpty($_.Hostname)))}).Count
    $DevicesUnkown = @($Devices | Where-Object {($_.Status -eq "Down") -and ([String]::IsNullOrEmpty($_.Hostname))}).Count

    $EndTime = Get-Date
    $ExecutionTimeMinutes = (New-TimeSpan -Start $StartTime -End $EndTime).Minutes
    $ExecutionTimeSeconds = (New-TimeSpan -Start $StartTime -End $EndTime).Seconds

    Write-Host "`n----------------------------------------------------------------------------------------------------`n"
    Write-Host "Devices Up:`t`t$DevicesUp" 
    Write-Host "Devices Down:`t`t$DevicesDown"
    Write-Host "Devices Unknown:`t$DevicesUnkown" 
    Write-Host "`n----------------------------------------------------------------------------------------------------`n"
    Write-Host "Script duration:`t$ExecutionTimeMinutes Minutes $ExecutionTimeSeconds Seconds`n" -ForegroundColor Yellow
    Write-Host "Script ($ScriptFileName) exit at $EndTime" -ForegroundColor Green
            
    ### return custom psobject with network informations

    if($ActiveOnly)
    {
        return $Devices | Where-Object {$_.Status -eq "Up"}
    }
    else
    {
        return $Devices
    }
}
