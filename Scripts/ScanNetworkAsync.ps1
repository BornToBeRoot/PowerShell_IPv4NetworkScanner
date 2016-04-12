###############################################################################################################
# Language     :  PowerShell 4.0
# Filename     :  ScanNetworkAsync.ps1
# Autor        :  BornToBeRoot (https://github.com/BornToBeRoot)
# Description  :  Powerful asynchronus IP-Scanner for PowerShell
# Repository   :  https://github.com/BornToBeRoot/PowerShell_Async-IPScanner
###############################################################################################################

<#
    .SYNOPSIS
    Powerful asynchronous IP-Scanner which returns a custom PowerShell-Object with basic informations about the 
    scanned IP-Range include IP-Address, Hostname (with FQDN) and Status.

    .DESCRIPTION
    I built this powerful asynchronous IP-Scanner, because every script i found on the Internet was very slow. 
    Most of them do there job, but ping every IP/Host in sequence and/or no one could ping more than a Subnet with 
	more than /24 hosts. 
    
    This Script can scan every IP-Range you want. To do this, just enter a Start IP-Address and an End IP-Address.
    You don't need a specific subnetmask (for example 172.16.1.47 to 172.16.2.5 would work).
    
    I use the PowerShell-RunspacePool in this script, to run the ICMP requests, DNS resolve etc. asynchron.

	You can modify the threads at the same time, the wait time if all threads are busy and the tries for each IP 
	in the parameter (use Get-Help for more details).
  
	If all IPs are finished with scanning, the script returns a custom PowerShell-Object which include IP-Address, 
	Hostname (with FQDN) and the Status (Up or Down). If you use the parameter "-GetMAC" it also would return 
	the MAC (with Vendor) and with the parameter "-ExtendedInformations" you can get the IPv6Address (if available), 
	BufferSize, ResponseTime (ms) and TTL. You can easily process this PSObject in a foreach-loop like every other 
	object in PowerShell.
    
    If you found a bug or have some ideas to improve this script... Let me know. You find my Github profile in 
    the links below.
                
    .EXAMPLE
    .\ScanNetworkAsync.ps1 -StartIPAddress 192.168.1.1 -EndIPAddress 192.168.1.200 -GetMAC
    
    .EXAMPLE
    .\ScanNetworkAsync.ps1 -StartIPAddress 172.16.0.1 -EndIPAddress 172.16.1.254 -Threads 100 -Tries 2 -IncludeInactive

    .LINK
    Github Profil:         https://github.com/BornToBeRoot
    Github Repository:     https://github.com/BornToBeRoot/PowerShell_Async-IPScanner
#>

[CmdletBinding()]
Param(
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
		HelpMessage='Set the maximum number of threads at the same time (Default=256)')]
	[Int32]$Threads=256,
	
	[Parameter(
		Position=3,
		HelpMessage='Set the maximum number of ICMP checks for each IP (Default=2)')]
	[Int32]$Tries=2,

    [Parameter(
        Position=4,
        HelpMessage='Show inactive devices in result (Default=Disabled)')]
    [switch]$IncludeInactive,
    
    [Parameter(
        Position=5,
        HelpMessage='Enable or disable DNS resolving (Default=Enabled')]
    [switch]$ResolveDNS=$true,

    [Parameter(
        Position=6,
        HelpMessage='Get MAC-Address from IP-Address (Only work in the same subnet) (Default=Disabled)')]  
    [switch]$GetMAC,

	[Parameter(
		Position=7,
		HelpMessage='Try to get extendend informations like BufferSize, ResponseTime and TTL')]
	[switch]$ExtendedInformations,

    [Parameter(
        Position=8,
        HelpMessage='Update IEEE Standards Registration Authority from IEEE.org (https://standards.ieee.org/develop/regauth/oui/oui.csv)')]
    [switch]$UpdateListFromIEEE  
)

Begin{
	# Time when the script starts
    $StartTime = Get-Date   

    # Script path and filename
    $Script_Startup_Path = Split-Path -Parent $MyInvocation.MyCommand.Path
    $ScriptFileName = $MyInvocation.MyCommand.Name      
   
    # IEEE ->  The Public Listing For IEEE Standards Registration Authority -> CSV-File
    $IEEE_MACVendorList_WebUri = "http://standards.ieee.org/develop/regauth/oui/oui.csv"

    # Local path to MAC vendor list
    $CSV_MACVendorList_Path = "$Script_Startup_Path\IEEE_Standards_Registration_Authority.csv"
    $CSV_MACVendorList_BackupPath = "$Script_Startup_Path\IEEE_Standards_Registration_Authority.csv.bak"
    
	# Integrated Update function for IEEE MAC vendor list
    if($UpdateListFromIEEE)
    {
        try{
            Write-Host "Updating IEEE Standards Registration Authority from IEEE.org...`t" -ForegroundColor Gray -NoNewline
            
            # Save file, before download a new version     
            if([System.IO.File]::Exists($CSV_MACVendorList_Path))
            {
                Rename-Item -Path $CSV_MACVendorList_Path -NewName $CSV_MACVendorList_BackupPath
            }

            # Download csv-file from IEEE
            Invoke-WebRequest -Uri $IEEE_MACVendorList_WebUri -OutFile $CSV_MACVendorList_Path

            # Remove Backup, if no error
            if([System.IO.File]::Exists($CSV_MACVendorList_BackupPath))
            {
                Remove-Item -Path $CSV_MACVendorList_BackupPath
            }

            Write-Host "OK" -ForegroundColor Green
        }
        catch{            
            # On error: cleanup downloaded file and restore backup
            if([System.IO.File]::Exists($CSV_MACVendorList_Path))
            {
                Remove-Item -Path $CSV_MACVendorList_Path
            }

            if([System.IO.File]::Exists($CSV_MACVendorList_BackupPath))
            {
                Rename-Item -Path $CSV_MACVendorList_BackupPath -NewName $CSV_MACVendorList_Path
            }

            $ErrorMsg = $_.Exception.Message
            
            Write-Host "Update IEEE Standards Registration Authority from IEEE.org failed with the follwing error message: $ErrorMsg"  -ForegroundColor Red
        }        
    }  
    elseif(($GetMAC) -and (-Not([System.IO.File]::Exists($CSV_MACVendorList_Path))))
    {   
        Write-Host 'No CSV-File to assign vendor with MAC-Address found! Use the parameter "-UpdateListFromIEEE" to download the latest version from IEEE.org. This warning doesn`t affect the scanning procedure.' -ForegroundColor Yellow
    }   
        
    if(($GetMAC) -and ([System.IO.File]::Exists($CSV_MACVendorList_Path)))
    { 
        $AssignMACtoVendorList = $true 
    } 
    else 
    { 
        $AssignMACtoVendorList = $false 
    }
    
    ### - - - Include functions - - - ###
    # Function to convert IPv4-Address from and to Int64
    
    # You can find this two functions in the following script:      https://gallery.technet.microsoft.com/scriptcenter/List-the-IP-addresses-in-a-60c5bb6b#content 
    # Published under the MS-LPL license you can fin here:          https://www.openhub.net/licenses/mslpl
    function IPtoInt64() { 
        param ($IPAddr) 
     
        $Octets = $IPAddr.split(".") 
        return [long]([long]$Octets[0]*16777216 + [long]$Octets[1]*65536 + [long]$Octets[2]*256 + [long]$Octets[3]) 
    } 
    
    function Int64toIP() { 
        param ([long]$Int) 

        return (([System.Math]::Truncate($Int/16777216)).ToString() + "." + ([System.Math]::Truncate(($Int%16777216)/65536)).tostring() + "." + ([System.Math]::Truncate(($int%65536)/256)).ToString() + "." + ([System.Math]::Truncate($int%256)).ToString())
    }			
    ### - - - - - - - - - - - - - - - ###

    $StartIPAddress_Int64 = IPtoInt64 -IPAddr $StartIPAddress.ToString()
    $EndIPAddress_Int64 = IPtoInt64 -IPAddr $EndIPAddress.ToString()

    $IPRange_Int64 = ($EndIPAddress_Int64 - $StartIPAddress_Int64)

    # Validate IP-Range
    if($StartIPAddress_Int64 -gt $EndIPAddress_Int64)
    {
        Write-Host "Check your input! Invalid IP-Range... (-EndIPAddress can't be lower than -StartIPAddress)" -ForegroundColor Red
        exit
    }

	# Some User-Output (settings)
    Write-Host "`nScript ($ScriptFileName) started at $StartTime" -ForegroundColor Green
    Write-Host "`n+=-=-=-=-=-=-=-=-=-=-=-=-= Settings =-=-=-=-=-=-=-=-=-=-=-=-=`n|"
    Write-Host "|  IP-Range:`t`t$StartIPAddress - $EndIPAddress"
    Write-Host "|  Threads:`t`t$Threads"
    Write-Host "|  Tries:`t`t$Tries"
    Write-Host "|`n+============================================================`n"      
}

Process{ 
	# Scriptblock --> will run in runspaces (threads)...
    [System.Management.Automation.ScriptBlock]$ScriptBlock = {
        Param(
			$IPv4Address,
			$Tries,
			$IncludeInactive,
			$ResolveDNS,
			$GetMac,
			$ExtendedInformations
		)

        # +++ Send ICMP requests +++
        $Status = [String]::Empty

		for($i = 0; $i -lt $Tries; i++)
		{
			try{
				$PingObj = New-Object System.Net.NetworkInformation.Ping
				
				$Timeout = 1000
				$Buffer = New-Object Byte[] 32
				
				$PingResult = $PingObj.Send($IPv4Address, $Timeout, $Buffer)

				if($PingResult.Status -eq "Success")
				{
					$Status = "Up"
					
					# Exit loop, if host is reachable
					break
				}
				elseif($i -eq ($Tries -1))
				{
					$Status = "Down"
				}
			}
			catch
			{
				$Status = "Down"

				# Exit loop, if there is an error
				break
			}
		}

		# +++ Resolve DNS +++
		$Hostname = [String]::Empty     

        if($ResolveDNS -and ($Status -eq "Up" -or $IncludeInactive))
        {   	
		    try{ 
                $Hostname = ([System.Net.Dns]::GetHostEntry($IPv4Address).HostName)
            } 
            catch { } # No DNS                    
     	}
     
        # +++ Get MAC-Address +++
		$MAC = [String]::Empty 

        if($GetMAC -and ($Status -eq "Up"))
        {
            $Arp_Result = (arp -a ).ToUpper()
			           
			foreach($Line in $Arp_Result)
            {
                if($Line.TrimStart().StartsWith($IPv4Address))
                {
					$MAC = [Regex]::Matches($Line,"([0-9A-F][0-9A-F]-){5}([0-9A-F][0-9A-F])").Value
                }
            }

            if([String]::IsNullOrEmpty($MAC))
            {
                try{              
                    $Nbtstat_Result = nbtstat -A $IPv4Address | Select-String "MAC"
                    $MAC = [Regex]::Matches($Nbtstat_Result, "([0-9A-F][0-9A-F]-){5}([0-9A-F][0-9A-F])").Value
                }  
                catch{ } # No MAC   
            }     
        }

		# Get extended informations (from PingResult)
		$BufferSize = [String]::Empty 
		$ResponseTime = [String]::Empty 
		$ResponseTimeToLive = [String]::Empty 

        if($ExtendedInformations -and ($Status -eq "Up"))
		{
			try{
				$BufferSize =  $PingResult.Buffer.Length
				$ResponseTime = $PingResult.RoundtripTime
				$TTL = $PingResult.Options.Ttl
			}
			catch{} # Failed to get extended informations			
		}	
		
		# Built custom PSObject
		$Result = New-Object -TypeName PSObject   
        
		Add-Member -InputObject $Result -MemberType NoteProperty -Name IPv4Address -Value $IPv4Address
		
		if($ResolveDNS -and ($Status -eq "Up" -or $IncludeInactive)) # Include DNS
		{ 
            Add-Member -InputObject $Result -MemberType NoteProperty -Name Hostname -Value $Hostname 
		}

		if($GetMAC -and ($Status -eq "Up")) # Include MAC
		{ 
            Add-Member -InputObject $Result -MemberType NoteProperty -Name MAC -Value $MAC 
		}

		if($ExtendedInformations -and ($Status -eq "Up")) # Include extended informations
		{
			Add-Member -InputObject $Result -MemberType NoteProperty -Name BufferSize -Value $BufferSize
			Add-Member -InputObject $Result -MemberType NoteProperty -Name ResponseTime -Value $ResponseTime
			Add-Member -InputObject $Result -MemberType NoteProperty -Name TTL -Value $TTL
		}

        Add-Member -InputObject $Result -MemberType NoteProperty -Name Status -Value $Status	
		
		return $Result      
    }            
        
	# Setting up RunspacePool
	Write-Host "Setting up RunspacePool...`t`t" -ForegroundColor Yellow -NoNewline

    $RunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Threads, $Host)
    $RunspacePool.Open()
    $Jobs = @()
	
    Write-Host "[" -ForegroundColor Gray -NoNewline; Write-Host "Done" -ForegroundColor Green -NoNewline; Write-Host "]" -ForegroundColor Gray	
	
    # Setting up jobs
	Write-Host "Setting up jobs...`t`t`t" -ForegroundColor Yellow -NoNewline
    
    for ($i = $StartIPAddress_Int64; $i -le $EndIPAddress_Int64; $i++) 
    { 
        $IPv4Address = Int64toIP -Int $i                

		# Create hashtable to pass parameters
		$ScriptParams = @{
			IPv4Address = $IPv4Address
			Tries = $Tries
			IncludeInactive = $IncludeInactive
			ResolveDNS = $ResolveDNS
			GetMac = $GetMac
			ExtendedInformations = $ExtendedInformations
		}       

		# Calculate percent finished
        if($IPRange_Int64 -gt 0) 
		{ 
			$Progress_Percent = (($i - $StartIPAddress_Int64) / $IPRange_Int64) * 100 
		} 
		else 
		{ 
			$Progress_Percent = 100 
		}

        Write-Progress -Activity "Setting up jobs..." -Id 1 -Status "Current IP-Address: $IPv4Address" -PercentComplete ($Progress_Percent) 
						 
		# Create job
        $Job = [System.Management.Automation.PowerShell]::Create().AddScript($ScriptBlock).AddParameters($ScriptParams)
        $Job.RunspacePool = $RunspacePool
        $Jobs += New-Object PSObject -Property @{
            RunNum = $i - $StartIPAddress_Int64
            Pipe = $Job
            Result = $Job.BeginInvoke()
        }				
    }
	
    Write-Host "[" -ForegroundColor Gray -NoNewline; Write-Host "Done" -ForegroundColor Green -NoNewline; Write-Host "]" -ForegroundColor Gray	
	
	# Wait until all Jobs are finished
	Write-Host "Waiting for jobs to complete...`t`t" -ForegroundColor Yellow -NoNewline
    
    Do {
        Write-Progress -Activity "Waiting for jobs to complete... ($($Threads - $($RunspacePool.GetAvailableRunspaces())) of $Threads threads running)" -Id 1 -PercentComplete (($Jobs.count - $($($Jobs | Where-Object {$_.Result.IsCompleted -eq $false}).Count)) / $Jobs.Count * 100) -Status "$(@($($Jobs | Where-Object {$_.Result.IsCompleted -eq $false})).Count) remaining..."

		Start-Sleep -Milliseconds 500
    } While ($Jobs.Result.IsCompleted -contains $false)
    
    Write-Progress -Activity "All Jobs completed!" -Id 1 -Completed

    Write-Host "[" -ForegroundColor Gray -NoNewline; Write-Host "Done" -ForegroundColor Green -NoNewline; Write-Host "]" -ForegroundColor Gray		
	
	Write-Host "Process results...`t`t`t" -ForegroundColor Yellow -NoNewline
    
    # Built global array
    $Job_Results = @()   
    
    # Get results and fill the array
    foreach ($Job in $Jobs)
    {
        $Job_Results += $Job.Pipe.EndInvoke($Job.Result)
		$Job.Pipe.Dispose()
    }
	
	$RunspacePool.Close()
		
    Write-Host "[" -ForegroundColor Gray -NoNewline; Write-Host "Done" -ForegroundColor Green -NoNewline; Write-Host "]" -ForegroundColor Gray	

	# Process results and assign vendor to mac
    if($AssignMACtoVendorList)
    {
        Write-Host "Assign vendor to MAC-Address...`t`t" -ForegroundColor Yellow -NoNewline

        $MAC_VendorList =  Import-Csv -Path $CSV_MACVendorList_Path | Select-Object "Assignment", "Organization Name"

        $Results_Vendor_Assigned = @()

        foreach($Job_Result in $Job_Results)
        {
            $Vendor = [String]::Empty

            if(-not([String]::IsNullOrEmpty($Job_Result.MAC)))
            {
                $MACVendor_Search = $Job_Result.MAC.Replace("-","").Substring(0,6)

                foreach($MAC_VendorEntry in $MAC_VendorList)
                {
                    if($MAC_VendorEntry.Assignment -eq $MACVendor_Search)
                    {
                        $Vendor = $MAC_VendorEntry."Organization Name"

                        break # Don't show multiple results
                    }
                }
            }                    

            # Built new custom PSObject
            $Result_Vendor_Assigned = New-Object -TypeName PSObject
            Add-Member -InputObject $Result_Vendor_Assigned -MemberType NoteProperty -Name IPv4Address -Value $Job_Result.IPv4Address   

			if($ResolveDNS) # Include DNS
			{ 
				Add-Member -InputObject $Result_Vendor_Assigned -MemberType NoteProperty -Name Hostname -Value $Job_Result.Hostname 
			}    

			Add-Member -InputObject $Result_Vendor_Assigned -MemberType NoteProperty -Name MAC -Value $Job_Result.MAC   
            Add-Member -InputObject $Result_Vendor_Assigned -MemberType NoteProperty -Name Vendor  -Value $Vendor   

			if($ExtendedInformations) # Include extended informations
			{		
				Add-Member -InputObject $Result_Vendor_Assigned -MemberType NoteProperty -Name BufferSize -Value $Job_Result.BufferSize
				Add-Member -InputObject $Result_Vendor_Assigned -MemberType NoteProperty -Name ResponseTime -Value $Job_Result.ResponseTime
				Add-Member -InputObject $Result_Vendor_Assigned -MemberType NoteProperty -Name TTL -Value $Job_Result.TTL
            }

			Add-Member -InputObject $Result_Vendor_Assigned -MemberType NoteProperty -Name Status -Value $Job_Result.Status	

            # Add new object to array
            $Results_Vendor_Assigned += $Result_Vendor_Assigned
        }        

        Write-Host "[" -ForegroundColor Gray -NoNewline; Write-Host "Done" -ForegroundColor Green -NoNewline; Write-Host "]" -ForegroundColor Gray	
    }
}

End {  
    # If no XML-File to assign, return PSObject without Vendor
    if($AssignMACtoVendorList) 
    { 
        $Results = $Results_Vendor_Assigned 
    } 
    else 
    { 
        $Results = $Job_Results 
    }

    # Time when the Script finished
    $EndTime = Get-Date

    # Calculate the time between Start and End
    $ExecutionTimeMinutes = (New-TimeSpan -Start $StartTime -End $EndTime).Minutes
    $ExecutionTimeSeconds = (New-TimeSpan -Start $StartTime -End $EndTime).Seconds
        
    # Some User-Output with Device UP/Down and execution time
    Write-Host "`n+=-=-=-=-=-=-=-=-=-=-=-=-=  Result  =-=-=-=-=-=-=-=-=-=-=-=-=`n|"
    Write-Host "|  IPs Scanned:`t`t$($Results.Count)"
    Write-Host "|  Devices Up:`t`t$(@($Results | Where-Object {($_.Status -eq "Up")}).Count)" 
    Write-Host "|`n+============================================================`n"
    Write-Host "Script duration:`t$ExecutionTimeMinutes Minutes $ExecutionTimeSeconds Seconds`n" -ForegroundColor Yellow
    Write-Host "Script ($ScriptFileName) exit at $EndTime`n" -ForegroundColor Green
            
    # Return custom psobject with network informations
    if($IncludeInactive) 
	{ 
		return $Results 
	} 
	else 
	{ 
		return $Results | Where-Object {$_.Status -eq "Up"} 
	} 
}
