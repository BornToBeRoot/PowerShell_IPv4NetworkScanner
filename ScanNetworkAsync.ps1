###############################################################################################################
# Language     :  PowerShell 4.0
# Script Name  :  ScanNetworkAsync.ps1
# Autor        :  BornToBeRoot (https://github.com/BornToBeRoot)
# Description  :  Asynchronus IP-Scanner
# Repository   :  https://github.com/BornToBeRoot/PowerShell-Async-IPScanner
###############################################################################################################

<#
    .SYNOPSIS
    Asynchronous IP-Scanner which returns a custom PowerShell object with basic informations about the 
    scanned IP-Range include IP-Address, Hostname (with FQDN) and Status.

    .DESCRIPTION
    I built this powerful asynchronous IP-Scanner, because every script i found on the Internet was very slow. 
    Most of them do there job, but ping every IP/Host in sequence and/or no one could ping more than /24. 
    This is Ok if you have a few host, but if you want to scan a large IP-Range, you need a lot of coffee :)

    This Script can scan every IP-Range you want. To do this, just enter a Start IP-Address and an End IP-Address.
    You don't need a specific subnetmask (for example 172.16.1.47 to 172.16.2.5 would work).
    
    You can modify the threads at the same time, the wait time if all threads are busy and the tries for each 
    IP in the parameter (use Get-Help for more details).
    
    If all IPs are finished scanning, the script returns a custom PowerShell object which include IP-Address, 
    Hostname (with FQDN) and the Status (Up or Down). You can easily process this PSObject in a foreach-loop 
    like every other object in PowerShell.
    
    If you found a bug or have some ideas to improve this script... Let me know. You find my Github profile in 
    the links below.
                
    .EXAMPLE
    ScanNetworkAsync.ps1 -StartIPAddress 192.168.1.1 -EndIPAddress 192.168.1.200
    
    .EXAMPLE
    ScanNetworkAsync.ps1 -StartIPAddress 172.16.0.1 -EndIPAddress 172.16.1.254 -Threads 50 -Tries 2 -ActiveOnly

    .LINK
    Github Profil:         https://github.com/BornToBeRoot
    Github Repository:     https://github.com/BornToBeRoot/PowerShell-Async-IPScanner
#>

[CmdletBinding()]
param(
	[Parameter(
		Position=0,
		Mandatory=$true,
		HelpMessage='Start IP-Address like 172.16.0.1')]
	[IPAddress]$StartIPAddress,
	
	[Parameter(
		Position=1,
		Mandatory=$true,
		HelpMessage='End IP-Address like 172.16.1.254')]
	[IPAddress]$EndIPAddress,

	[Parameter(
		Position=2,
		Mandatory=$false,
		HelpMessage='Maximum threads at the same time (Default 256)')]
	[Int32]$Threads=256,
	
	[Parameter(
		Position=3,
		Mandatory=$false,
		HelpMessage='Maximum number of Test-Connection checks for each IP (Default 2)')]
	[Int32]$Tries=2,

    [Parameter(
        Position=4,
        Mandatory=$false,
        HelpMessage='Show inactive devices in result')]
    [switch]$IncludeInactive      
)

begin{
	# Time when the script starts
    $StartTime = Get-Date

    # Script FileName
    $ScriptFileName = $MyInvocation.MyCommand.Name      
        
    ### - - - Include functions - - - ###
    # Function to convert IPv4-Address from and to Int64
    
    # You can find this two functions in the following script:      https://gallery.technet.microsoft.com/scriptcenter/List-the-IP-addresses-in-a-60c5bb6b#content 
    # Published under the MS-LPL license you can fin here:          https://www.openhub.net/licenses/mslpl
    function IPtoInt64 () { 
        param ($IPAddr) 
 
        $Octets = $IPAddr.split(".") 
        return [long]([long]$Octets[0]*16777216 +[long]$Octets[1]*65536 +[long]$Octets[2]*256 +[long]$Octets[3]) 
    } 
    
    function Int64toIP() { 
        param ([long]$Int) 

        return (([System.Math]::Truncate($Int/16777216)).ToString() + "." + ([System.Math]::Truncate(($Int%16777216)/65536)).tostring() + "." + ([System.Math]::Truncate(($int%65536)/256)).ToString() + "." + ([System.Math]::Truncate($int%256)).ToString())
    }
    ### - - - - - - - - - - - - - - - ###

    $StartIPAddress_Int64 = IPtoInt64 -IPAddr $StartIPAddress.ToString()
    $EndIPAddress_Int64 = IPtoInt64 -IPAddr $EndIPAddress.ToString()
    $IPRange_Int64 = ($EndIPAddress_Int64 - $StartIPAddress_Int64)

    # Check if Start IP is greater than End IP
    if($StartIPAddress_Int64 -gt $EndIPAddress_Int64)
    {
        Write-Host "Check your input! Invalid IP-range... (-EndIPAddress can't be lower than -StartIPAddress)" -ForegroundColor Red
        exit
    }

	# Some user-output about the selected or default settings	
    Write-Host "`nScript ($ScriptFileName) started at $StartTime" -ForegroundColor Green
    Write-Host "`n----------------------------------------------------------------------------------------------------`n"
    Write-Host "IP-Range:`t`t$StartIPAddress - $EndIPAddress"
    Write-Host "Threads:`t`t$Threads"
    Write-Host "Tries:`t`t`t$Tries"
    Write-Host "`n----------------------------------------------------------------------------------------------------`n"      
}

Process{ 
    # Scriptblock that will run in runspaces (threads)...
    [System.Management.Automation.ScriptBlock]$ScriptBlock = {
        ### Parameters
        $IPv4Address = $args[0]
        $Tries = $args[1]
        $IncludeInactive = $args[2]
               
        # Test if device is available
        if(Test-Connection -ComputerName $IPv4Address -Count $Tries -Quiet) { $Status = "Up" } else { $Status = "Down" }		
		  
        $Hostname = [String]::Empty 

        # Resolve DNS
        if($Status -eq "Up" -or $IncludeInactive)
        {   	
		    try { $Hostname = ([System.Net.Dns]::GetHostEntry($IPv4Address).HostName).ToUpper() }
            catch { } # No DNS found                        
      	}

        ### Built custom PSObject
		$Result = New-Object -TypeName PSObject
        Add-Member -InputObject $Result -MemberType NoteProperty -Name IPv4Address -Value $IPv4Address
        Add-Member -InputObject $Result -MemberType NoteProperty -Name Hostname -Value $Hostname            
		Add-Member -InputObject $Result -MemberType NoteProperty -Name Status -Value $Status
		
        return $Result      
    }            
        
    # Setting up runspaces
    $RunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1,$Threads, $Host)
    $RunspacePool.Open()
    $Jobs = @()

    Write-Host "`nScanning IPs..." -ForegroundColor Yellow

    # Setting up jobs
    for ($i = $StartIPAddress_Int64; $i -le $EndIPAddress_Int64; $i++) 
    { 
        $IPv4Address = Int64toIP -Int $i

        Write-Progress -Activity "Setting up jobs..." -Id 1 -Status "Current IP-Address: $IPv4Address" -PercentComplete ((($i - $StartIPAddress_Int64) / $IPRange_Int64) * 100)
                      
        $Job = [System.Management.Automation.PowerShell]::Create().AddScript($ScriptBlock).AddArgument($IPv4Address).AddArgument($Tries).AddArgument($IncludeInactive)
        $Job.RunspacePool = $RunspacePool
        $Jobs += New-Object PSObject -Property @{
            RunNum = $i - $StartIPAddress_Int64
            Pipe = $Job
            Result = $Job.BeginInvoke()
        }
    }
        
    # Wait until all Jobs are finished
    Do {
        Start-Sleep -Milliseconds 500
              
        Write-Progress -Activity "Waiting for jobs ($($Threads - $($RunspacePool.GetAvailableRunspaces())) of $Threads threads running)" -Id 1 -PercentComplete (($Jobs.count - $($($Jobs | Where-Object {$_.Result.IsCompleted -eq $false}).Count)) / $Jobs.Count * 100) -Status "$(@($($Jobs | Where-Object {$_.Result.IsCompleted -eq $false})).Count) remaining..."
                                
    } While ($Jobs.Result.IsCompleted -contains $false)
    
    # Built global array
    $Results = @()
   
    # Get results and fill the array
    foreach ($Job in $Jobs)
    {
        $Results += $Job.Pipe.EndInvoke($Job.Result)
    }
    
    Write-Host "`nScan finished!" -ForegroundColor Yellow        
}

End {  
    # Time when the Script finished
    $EndTime = Get-Date

    # Calculate the time between Start and End
    $ExecutionTimeMinutes = (New-TimeSpan -Start $StartTime -End $EndTime).Minutes
    $ExecutionTimeSeconds = (New-TimeSpan -Start $StartTime -End $EndTime).Seconds
        
    # Some User-Output with Device UP/Down and execution time
    Write-Host "`n----------------------------------------------------------------------------------------------------`n"
    Write-Host "Devices Up:`t`t$(@($Results | Where-Object {($_.Status -eq "Up")}).Count)" 
    Write-Host "Devices Down:`t`t$(@($Results | Where-Object {($_.Status -eq "Down")}).Count)"
    Write-Host "`n----------------------------------------------------------------------------------------------------`n"
    Write-Host "Script duration:`t$ExecutionTimeMinutes Minutes $ExecutionTimeSeconds Seconds`n" -ForegroundColor Yellow
    Write-Host "Script ($ScriptFileName) exit at $EndTime`n" -ForegroundColor Green
            
    # Return custom psobject with network informations
    if($IncludeInactive) { return $Results } else { return $Results | Where-Object {$_.Status -eq "Up"} } 
}