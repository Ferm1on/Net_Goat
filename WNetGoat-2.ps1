# This script will gather network information data for later analysis. Specifically it will gather client network settings through ipconfig and netsh and Get-NetAdapter.
# It will record the interface throughput to a file and it will record pings to internal and external server to a file.
# You must have wireshark and dumpcap installed. You should addp C:\Program Files\Wireshark to your PATH variables on Enviromental Variables.
# To run this script you must run a Powershell 7 or higher terminal window and change Execution Policy to Unrestricted by running the following command.
# Set-ExecutionPolicy -ExecutionPolicy Unrestricted
# OR
# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
# Dependencies: netsh, dumpcap, PowerShell 7 or higher: $PSVersionTable
#
# Wireshark filter: tcp.analysis.retransmission || tcp.analysis.fast_retransmission || tcp.analysis.lost_segment || tcp.analysis.duplicate_ack
# FUNCTIONS DEFINITION

# This function will cause the thread to wait for a certain number of seconds. Use this function instead of Start-Sleep if you want for the Thread-Jobs to continue running.
function Wait-Timer {
    param(
        [Uint16]$Seconds #Number of seconds to wait for.
    )
    # Function Body
    try {
        $Timeout = New-TimeSpan -Seconds $Seconds
        $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Output "`tWaiting for $Seconds seconds before proceesing"
        while ($Stopwatch.Elapsed -lt $Timeout) {
        }
        $Stopwatch.stop()
    } catch {
        Write-Output "`tAn error has occured or function was terminated early. Possiblle error 
       `" Value was either too large or too small for UInt16.`""
    }
}

# This function gathers network statistic data and writes it out to a output file. If the file does not exists it creates it the file.
# Data gathered: Hostname, Get-NetAdapter, ipconfig /all, netsh.
function Write-NetSettings {
    param (
    [string]$OutputFile # File to write results to.
	)
    # Function Body
    Write-Output "-----------------------------------------------------------------------------------------------------------------------" | Tee-Object -FilePath $OutputFile -Append
    Write-Output "`t `t Gathering $env:COMPUTERNAME Networkd Adapter Settings: $(Get-Date)" | Tee-Object -FilePath $OutputFile -Append
    Write-Output "-----------------------------------------------------------------------------------------------------------------------" | Tee-Object -FilePath $OutputFile -Append
    Get-NetAdapter | Tee-Object -FilePath $OutputFile -Append
    Write-Output "-----------------------------------------------------------------------------------------------------------------------" | Tee-Object -FilePath $OutputFile -Append
    ipconfig /all | Tee-Object -FilePath $OutputFile -Append
    Write-Output "-----------------------------------------------------------------------------------------------------------------------" | Tee-Object -FilePath $OutputFile -Append
    netsh wlan show interfaces | Tee-Object -FilePath $OutputFile -Append
    Write-Output "-----------------------------------------------------------------------------------------------------------------------" | Tee-Object -FilePath $OutputFile -Append
    return
}


# This function will record the interface throughput data and save it to a file. 
# The file will have a header in the form of <Start Date and Time, Bytes/s> and value pairs, <elapsed time in s, throughput in Bytes/s>
# Notice that the results are the instantaneous throughput at a particular moment. Some of the throughput values will be zero if there are not allot of
# network activity as the recording starts.
function Write-ThroughputData {
    param (
    [string]$InterfaceName, # Interface to record throughput from.
    [UInt32]$RecordInterval=5, # Capture current throughput every X seconds. Default is 5.
    [double]$RecordLength=0, # How long in seconds to capture network throughput data. Default is 0, which means until process is terminated.
    [string]$Path='.' # Path to where the recorded file should be created in. Default is current directory.
    )
    # Setup Log File to record data to.
    $LogFile = "$Path\NetTPLog_$((Get-Date).ToString('ddMMyyHHmmss')).txt"
    "$(Get-Date),Bytes/s,Error" >> $LogFile
    # Input filtering
    if ($RecordInterval -le 0 -or $RecordLength -lt 0) {
        Write-output "0,0,Error: RecordInterval or RecordLength is less than 0, function is exiting." >> $LogFile
        return
    }

    # Function Body
    [double]$Count = 0
    try {
        $StartTime = (Get-Counter -Counter "\Network Interface(*$InterfaceName*)\Bytes Total/sec").Timestamp
    } Catch {
        # Format the ExecutionError variable to only have the Error text.
        if($ExecutionError.ErrorRecord){$ExecutionError = $ExecutionError.ErrorRecord}
        Write-Output "0,0,Error: Unable to retrieve counter data for interface '$InterfaceName'. $ExecutionError" >> $LogFile
        return
    }
    try {
        Write-Output "Logging network throughput to $LogFile..."
        while ($Count -lt $RecordLength -or $RecordLength -eq 0) {
            $LookUpTime = Measure-Command {
                $NetData = Get-Counter -Counter "\Network Interface(*$InterfaceName*)\Bytes Total/sec"
                "$((New-TimeSpan -Start $StartTime -End $NetData.TimeStamp).TotalSeconds),$($NetData.CounterSamples.CookedValue)" >> $LogFile
            }
            Start-Sleep -Seconds ((&{param($A,$B) if ($A -gt $B) {return $A - $B}} $RecordInterval $LookUpTime.TotalSeconds) + 0)
            $Count+=&{param($A,$B) if ($B -gt $A) {return $B} else {$A}} $RecordInterval $LookUpTime.TotalSeconds
        }
    } Catch {
        Write-Output "Recording stopped by user or due to an error."  | Tee-Object -FilePath $LogFile -Append
    }
}
# Create ScripBlock object in order to send it to Thread Worker (Start-ThreadJob)
$Write_ThroughputData = [ScriptBlock]::Create((Get-Command Write-ThroughputData -CommandType Function).Definition)

# This functions pings a target address for a number of seconds and records the latency into a file. 
# File header is <Target,Latency(ms)> and value pairs are <IP address or Domain Name,Milliseconds>
function Write-PingLatency {
    param (
        [string]$TargetAddress, # Taget address to ping.
        [UInt32]$RecordInterval=5, # Interval in seconds between ping atempts. Default is 5.
        [double]$RecordLength=0, # How long to ping for. Default is 0, which means until process is terminated.
        [string]$Path='.' # Path to where the recorded file should be created in. Default is current directory.
    )
    # Setup Log File to record data to.
    $LogFile = "$Path\Ping_($TargetAddress)_Log_$((Get-Date).ToString('ddMMyyHHmmss')).txt"
    "Target,Latency(ms),Status,Error" >> $LogFile
    # Input filtering
    if ($RecordInterval -le 0 -or $RecordLength -lt 0) {
        Write-output "$TargetAddress,0,N/A,Error: RecordInterval or RecordLength is less than 0, function is exiting." >> $LogFile
        return
    }

    # Function Body
    [double]$Count = 0
    $ExecutionError = $NULL
    try {
        Write-Output "Logging ping latency from $env:COMPUTERNAME to $TargetAddress to $LogFile..."
        while ($Count -lt $RecordLength -or $RecordLength -eq 0) {
            $LookUpTime = Measure-Command {
                $PingData = Test-Connection -TargetName $TargetAddress -Count 1 -ErrorVariable ExecutionError
                # Format the ExecutionError variable to only have the Error text.
                if($ExecutionError.ErrorRecord){$ExecutionError = $ExecutionError.ErrorRecord}
                "$($PingData.Address),$($PingData.Latency),$($PingData.Status),$ExecutionError" >> $LogFile
            }
            Start-Sleep -Seconds ((&{param($A,$B) if ($A -gt $B) {return $A - $B}} $RecordInterval $LookUpTime.TotalSeconds) + 0)
            $Count+=&{param($A,$B) if ($B -gt $A) {return $B} else {$A}} $RecordInterval $LookUpTime.TotalSeconds
            # Start-Sleep -Seconds $RecordInterval
            # $Count+=$RecordInterval
        }
    } Catch {
        Write-Output "$TargetAddress,0,N/A,$Error"  | Tee-Object -FilePath $LogFile -Append
    }
}
# Create ScripBlock object in order to send it to Thread Worker (Start-ThreadJob)
$Write_PingLatency = [ScriptBlock]::Create((Get-Command Write-PingLatency -CommandType Function).Definition)

# This function will atempt to resolve a domain name using a provided server and record to a file the resolution time.
# Note that the resolution time also includes the time it takes to run the command.
function Write-DNSLookUpSpeed {
    param (
        [string]$TargetAddress, # Domain Name or IP to attempt to resolve.
        [string]$TargetServer, # DNS to use for resolution..
        [UInt32]$RecordInterval=5, # Time between resolution attempts in seconds. Default is 5.
        [double]$RecordLength=0, # How long to keep resolving Domain Name in seconds. Default is 0, which means until process is terminated.
        [string]$Path='.' # Path to where the recorded file should be created in. Default is current directory.
    )
    # Setup Log File to record data to.
    $LogFile = "$Path\DNS($TargetServer)_LU($TargetAddress)_$((Get-Date).ToString('ddMMyyHHmmss')).txt"
    "LookUp Time in ms,Error" >> $LogFile
    # Input filtering
    if ($RecordInterval -le 0 -or $RecordLength -lt 0) {
        Write-output "RecordInterval or RecordLength is less than 0, function is exiting."
        return
    }

    # Function Body
    try {
        Write-Output "Logging LookUp time in ms from $TargetServer to $TargetAddress to $LogFile..."
        $Count = 0
        $ExecutionError = $NULL
        while ($Count -lt $RecordLength -or $RecordLength -eq 0) {
            $LookUpTime = Measure-Command {Resolve-DnsName -Name $TargetAddress -Type A -Server $TargetServer -ErrorVariable ExecutionError}
            # Format the ExecutionError variable to only have the Error text.
            if($ExecutionError.ErrorRecord){$ExecutionError = $ExecutionError.ErrorRecord}
            "$($LookUpTime.TotalMilliseconds),$ExecutionError" >> $LogFile
            Start-Sleep -Seconds ((&{param($A,$B) if ($A -gt $B) {return $A - $B}} $RecordInterval $LookUpTime.TotalSeconds) + 0)
            $Count+=&{param($A,$B) if ($B -gt $A) {return $B} else {$A}} $RecordInterval $LookUpTime.TotalSeconds
        }
    } Catch {
        Write-Output "0, $Error"  | Tee-Object -FilePath $LogFile -Append
    }
}
# Create ScripBlock object in order to send it to Thread Worker (Start-ThreadJob)
$Write_DNSLookUpSpeed = [ScriptBlock]::Create((Get-Command Write-DNSLookUpSpeed -CommandType Function).Definition)

# ---------------------------------------------------------------------------------------------------------------------------------------------
# SCRIPT BODY

# Initialize Parameters
# How long should script record for.
$GlobalRecordLength = 30

# Record Intervals for different functions
$ThroughputRecordInterval = 2
$PingRecordInterval = 5
$DNSRecordInterval = 15

# Addresses to ping. Addresses should be in IPv4 or Domain Name Formating.
# Getting current Gateway Address. # If the gateway is not found, set gateway name to NoGatewayFound
If(-not ($GatewayAddress = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue).NextHop)){$GatewayAddress = "NoGatewayFound"}
$AddressesToPing = @(${GatewayAddress},"www.amazon.com","www.google.com","www.microsoft.com")

# DNS Resolution Addresses and DNS Pairs. Resolves the Target using Server.
$DNS_Target_Servers = @(
    [PSCustomObject]@{Target = "www.amazon.com"; Server = "8.8.8.8"},
    [PSCustomObject]@{Target = "www.google.com"; Server = "8.8.8.8"},
    [PSCustomObject]@{Target = "www.microsoft.com"; Server = "8.8.8.8"}
    )

# Make directory to store files under and computer script path
$LogFolder = ".\NetLogs_$((Get-Date).ToString('ddMMyyHHmmss'))"
$ScriptPath = (Resolve-Path ".\NetGoatAnalyzer.py").Path
mkdir $LogFolder
# Create Current Network Settings File
$NetSettingsFile = "$LogFolder\NetSettings_$((Get-Date).ToString('ddMMyyHHmmss')).txt"

# ---------------------------------------------------------------------------------------------------------------------------------------------
# Start Workers

# dumpcap traffic capture
# Find index of Wi-Fi interface.
$InterfaceIndex=1
$InterfaceList = dumpcap -D
foreach($Interface in $InterfaceList){
    if($Interface -match "Wi-Fi"){
        break
    }
    $InterfaceIndex+=1
}
# Start dumpcap capture
Start-Process -FilePath "dumpcap" -ArgumentList "-i $InterfaceIndex -a duration:$GlobalRecordLength -w $LogFolder\WireSharkCapture_$((Get-Date).ToString('ddMMyyHHmmss')).pcapng"

# Start Network Througput Data worker.
$TP_job = Start-ThreadJob -ThrottleLimit 20 $Write_ThroughputData -ArgumentList "Wi-Fi", $ThroughputRecordInterval, $GlobalRecordLength, $LogFolder

# Start Ping worker.
$Ping_Jobs = @{}
Foreach($Target in $AddressesToPing) {
    $varName = "${Target}"
    $Ping_Jobs[$varName] = Start-ThreadJob -ThrottleLimit 20 $Write_PingLatency -ArgumentList $Target, $PingRecordInterval, $GlobalRecordLength, $LogFolder
}

# Start DNS Workers.
$DNS_Jobs = @{}
Foreach($DNS_LU in $DNS_Target_Servers) {
    $varName = "$($DNS_LU.Target)-$($DNS_LU.Server)"
    $DNS_Jobs[$varName] = Start-ThreadJob -ThrottleLimit 20 $Write_DNSLookUpSpeed -ArgumentList $DNS_LU.Target, $DNS_LU.Server, $DNSRecordInterval, $GlobalRecordLength, $LogFolder
}

# ---------------------------------------------------------------------------------------------------------------------------------------------

# Save Network Settings
Write-NetSettings -OutputFile $NetSettingsFile

# Waiting for workers to finish.
Write-Output "`tWaiting for all jobs to complete"

# Waiting for Throughput Worker
Wait-Job $TP_job.id

# Wait for Ping Workers
foreach ($job in $Ping_Jobs.Values) {
    Wait-Job $job.Id
}

# Wait for DNS Workers
foreach ($job in $DNS_Jobs.Values) {
    Wait-Job $job.Id
}

Write-Output "`tJobs Recordings Completed."

Write-Output "`tStarting Ping and DNS analysis."
Start-Process -FilePath "python" -WorkingDirectory $LogFolder -ArgumentList `"$ScriptPath`" -NoNewWindow

Write-Output "`tData analysis completed"
Write-Output "-----------------------------------------------------------------------------------------------------------------------"

pause
Write-Output " "

#-------------------------------------------------------------------------------------------------------------------------------------
# Future upgrade
# Fix dumpcap to work as a Start-ThreadJob instead
# Change the order of  $RecordInterval and $RecordLength variable to make it easyer to start workers with default value.
# Add Bot to start script automatically.

#
#$VideoToPlay = "https://www.youtube.com/embed/EDjb2nLSxDo?si=QBmSUptm4obNs3dc&autoplay=1&vq=hd2160"
#$edgeProcess = Start-Process "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -ArgumentList $VideoEmbeded -PassThru
#Stop-Process -Id $VideoProcess
# Stop all edge processes
#Get-Process msedge -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process $_.Id -Force }

# BUG: for the Write-ThroughputData  function, wireless card name might very.

