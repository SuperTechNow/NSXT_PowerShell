### Internal Functions
Function Select-NSXTServer {
    if( !$(test-path "$PSScriptRoot\NSXT_Servers.json") ){
        write-host "NSXT_Servers.json file is missing!" -ForegroundColor red -BackgroundColor Yellow
        exit(1)
    }

    $nsxt_list = get-content -raw -path "$PSScriptRoot\NSXT_Servers.json" | ConvertFrom-Json

    $inputNSXT = " "
    $confirmed = $false
    while(!$confirmed){
        while ($nsxt_list.NSXT -notcontains $inputNSXT){
            write-host "`n Select One NSX-T Server..." -ForegroundColor Green
            write-host ("#"*30) -ForegroundColor Yellow
            $nsxt_list | Out-String | Write-Host
            write-host ("#"*30) -ForegroundColor Yellow
            $inputNSXT = read-host -prompt "Please select a proper NSX-T Server"
        }

        Write-host "`nYou selected the following NSX-T Server:" -ForegroundColor Green
        $nsxt_list | where {$_.NSXT -like $inputNSXT} | Out-String | Write-Host
        $user_confirmed = read-host -Prompt "Please confirm Yes/No?"

        if ($user_confirmed -like "y*"){
            $confirmed = $true
        }else{
            $inputNSXT = " "
        }
    }
    Write-Host "`nNSX-T server '$inputNSXT' selected"  -ForegroundColor Green
    return $inputNSXT
}

Function Select-CSV {
    parma(
        [Parameter(ValueFromPipeline = $true, HelpMessage = "Enter CSV Path(s)")]
        [string[]]$file_path = $null,
        [string[]]$titleMesg
    )

    Write-Host "A window will prompt up on your primary monitor, asking to select a file" -ForegroundColor Yellow
    
    if(!$file_path) {
        add-type -AssemblyName System.Windows.Forms
        $current_dir = Get-Location
        $Dialog = New-Object System.Windows.Forms.OpenFileDialog
        $Dialog.InitialDirectory  = $current_dir.Path
        $Dialog.Title = $titleMesg
        $Dialog.Filter  = "CSV File(s)|*.csv"
        $Dialog.Multiselct = $false
        $Result = $Dialog.ShowDialog( (New-object System.Windows.Forms.Form -Property @{TopMost = $true}) )

        if($Result -eq 'OK') {
            Try {
                $file_path = $Dialog.FileNames
            }
            Catch{
                $file_path = $null
                exit
            }
        }else{
            #shows upon clicking cancel
            Write-Host "Notice: No file(s) selected."
            exit(1)
        }
    }

    Write-host "Selected file:" -ForegroundColor Green
    Write-Host $file_path
    Return $file_path

}


Function Confirm-File {
    param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true, HelpMessage  = "Need Input File Name")]
        [ValidateNotNullorEmpty()]$inputFile,

        [Parameter(ValueFromPipelineByPropertyName = $true, Mandatory = $true)]
        [ValidateNotNullorEmpty()]$Property
    )

    Write-Host "`nYour input file has the following content with $($inputFile.count) lines of data" -ForegroundColor Green
    Write-Host "$('#'*10)" -ForegroundColor yellow -nonewline
    write-host "(only first and last 5 rows are shown if the data is over 10 rows)" -ForegroundColor Green -nonewline
    write-host $('#'*10) -ForegroundColor Yellow

    if($inputFile.count -le 10){
        $inputFile | Format-Table -Property $Property | out-string -stream | write-host 
    }else{
        $inputFile | Select-Object -first 5 | ft -Property $Property | Out-String -stream | Write-Host
        Write-Host ("`n ."*3)
        $inputFile | Select-Object -last 5 | ft -Property $Property -HideTableHeaders | out-string -Stream | Write-Host
    }

    $confirmed = read-host -Prompt  "`n Please confirm the input file is correct! Yes/No?"

    if($confirmed -like "y*"){
        return $true
    }else{
        return $false
    }
}

Function Verify-IP{
    param(
        # Parameter help description
        [Parameter(ValueFromPipeline  = $true, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$IP
    )

    ## [1-9]? means [1-9] can exist or not; so [1-0]?[0-9] covers 0-99
    $octet = '(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
    $delim = '\.'
    $repeatTimes = '{3}'
    $sub = '(3[0-2]|[1-2]?[0-9])'
    $IPAddr = "($octet$delim)$repeatTimes$octet"
    $IPmatchPattern = "^$IPAddr$"
    $SubnetmatchPattern = "^$IPAddr/$sub$"
    $IPRangePattern = "^$IPAddr-$IPAddr$"
    $AllVerifiedIP = $true
<#     if ($IP -match "$IPRangePattern|$SubnetmatchPattern|$IPmatchPattern" ){
        $VerifiedIP = $true
    } #>

    switch -Regex ($IP) {
        $IPRangePattern {continue}
        $SubnetmatchPattern {continue}
        $IPmatchPattern {continue}
        default {$AllVerifiedIP = $false}
    }

    return $AllVerifiedIP
}

Function Verify-Port {
    param(
        [parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string[]]$Port
    )

    $validFormat = $true
    $portNum = "\d{1,5}"
    $singleUDPPortPattern = "^udp$portNum$"
    $singleTCPPortPattern = "^tcp$portNum$"
    $rangeUDPPortPattern = "^udp$portNum-$portNum"
    $rangeTCPPortPattern = "^tcp$portNum-$portNum"
    $anyPattern = "^any$"
    $icmpPattern = "^icmp"

    ## variables for checking duplicate ports
    $temp_UDPPortArray = @()
    $temp_TCPportArray = @()
    $Port = $Port -replace " ",""
    
    if ( ($port -match "[^any]") -and ($port -match "[any]") ) {
        $validFormat = $false
        write-host "`t`t Port 'Any' should not be combined with anything else!" -ForegroundColor Red
        Start-Sleep 1
    }

    switch -regex ($Port) {
        $singleUDPPortPattern {
            try {
                ## Replace prefix; convert to integer and Add port to the temp array for later duplicate port check
                $temp_UDPPortArray += [int]($_ -replace "udp", "")
                if ( [int]($_ -replace "udp", "") -gt 65535){
                    Write-Host "`t`t UDP Port $_ has a port number larger than 65535!" -ForegroundColor red
                    $validFormat = $false
                }
                
            }catch {
                Write-Host "`t`t UDP Port $_ has wrong format!" -ForegroundColor Red
                $validFormat = $false
            }
            continue
        }

        ## same for TCP port
        $singleTCPPortPattern {
            try {
                ## Replace prefix; convert to integer and Add port to the temp array for later duplicate port check
                $temp_TCPPortArray += [int]($_ -replace "tcp", "")
                if ( [int]($_ -replace "tcp", "") -gt 65535){
                    Write-Host "`t`t TCP Port $_ has a port number larger than 65535!" -ForegroundColor red
                    $validFormat = $false
                }
                
            }
            catch {
                Write-Host "`t`t TCP Port $_ has wrong format!" -ForegroundColor Red
                $validFormat = $false
            }
            continue
        }

        $rangeUDPPortPattern {
            try {
                ## Convert udpXXX-YYY -> array (xxx,yyy) 
                $range = ($_ -replace "udp","") -split "-" | ForEach-Object {Invoke-Expression $_}

                if ($range -gt 65535) {
                    Write-Host "`t`t Port range $_ has port number larger than 65535!" -ForegroundColor Red
                    $validFormat  = $false
                }

                if ($range[0] -ge $range[1]){
                    Write-Host "`t`t Port range $_'s first number equal or larger than the second number!" -ForegroundColor Red
                    $validFormat = $false
                }
                else{
                    ## Convert array (xxx,yyy) -> a series of number from xxx to yyy, and add them all to the temp udp port array
                    $temp_UDPPortArray += ($range[0]..$range[1])
                }
                
            }
            catch {
                Write-Host "`t`t Port range $_ has wrong format!" -ForegroundColor red

            }
            continue
        }

        $rangeTCPPortPattern {
            try {
                ## Convert udpXXX-YYY -> array (xxx,yyy) 
                $range = ($_ -replace "tcp","") -split "-" | ForEach-Object {Invoke-Expression $_}

                if ($range -gt 65535) {
                    Write-Host "`t`t Port range $_ has port number larger than 65535!" -ForegroundColor Red
                    $validFormat  = $false
                }

                if ($range[0] -ge $range[1]){
                    Write-Host "`t`t Port range $_'s first number equal or larger than the second number!" -ForegroundColor Red
                    $validFormat = $false
                }
                else{
                    ## Convert array (xxx,yyy) -> a series of number from xxx to yyy, and add them all to the temp udp port array
                    $temp_TCPPortArray += ($range[0]..$range[1])
                }
                
            }
            catch {
                Write-Host "`t`t Port range $_ has wrong format!" -ForegroundColor red

            }
            continue
        }

        $anyPattern {
            continue
        }

        $icmpPattern {
            continue
        }

        Default {
            Write-Host "`t`t $_ has wrong format!" -ForegroundColor Red
            $validFormat = $false
        }
    }

    ## Check duplicated port
    $dup_UDP = $temp_UDPPortArray | Group-Object | Where-Object {$_.count -gt 1}
    $dup_TCP = $temp_TCPportArray | Group-Object | Where-Object {$_.count -gt 1}

    if ( $dup_UDP ){
        Write-Host "`t`tDuplicated UDP ports found: $($dup_UDP.name -join ';') " -ForegroundColor Red
        $validFormat = $false
    }

    if ( $dup_TCP) {
        Write-Host "`t`tDuplicated TCP ports found: $($dup_TCP.name -join ';') " -ForegroundColor Red
        $validFormat = $false
    }

    return $validFormat
}


Function Split-NSXTPorts{
    <#
    .SYNOPSIS
     NSX
    
    .DESCRIPTION
    Long description
    
    .PARAMETER InputArray
    Parameter description
    
    .PARAMETER SubArraySize
    Parameter description
    
    .EXAMPLE
    An example
    
    .NOTES
    General notes
    #>

    param(# Service port array
    [Parameter(ValueFromPipeline = $true, Position = 0, Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript( {$_ -is [array] })]
    [array[]]$InputArray,
    # Define the size of sub array
    [Parameter(ValueFromPipelineByPropertyName = $true, position = 1, Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript( {$_ -is [int] })]
    [int]$SubArraySize
    )

    $outputArray = @()
    $port_count = 0
    $array = @()

    ## NSX-T port range counts as 2 values in service entity
    ## Each service entity should not exceed value of 15
    ## Loop through ports and make a list of sub array with defined size or defined size -1 
    foreach ($port in $InputArray) {

        ## If it's a port range, check variable $port_count,
        ##  a. if it's less or equal to $SubArraySize-2, add the range to $array and increase $port_count by 2
        ##  b. if it's $SubArraySize-1 or $SubArraySize, add $array to $outputArray as an individual array, reset $array and then add $port to it, reset $port_count to 2
        if($port -like "*-*"){
            if($port_count -le $SubArraySize-2) {
                $array += $port
                $port_count +=2
            }
            else{
                $outputArray += ,$array
                $array = @()
                $array += $port
                $port_count =2
            }
        }
        ## If it's a port, check variable $port_count,
        ##  a. if it's less or equal to $SubArraySize-1, add the range to $array and increase $port_count by 1
        ##  b. if it's $SubArraySize, add $array to $outputArray as an individual array, reset $array and then add $port to it, reset $port_count to 1
        else{
            if($port_count -le $SubArraySize-1){
                $array +=$port
                $port_count +=1
            }
            else{
                $outputArray += ,$array
                $array = @()
                $array += $port
                $port_count = 1
            }
        }
    }

    ## At the end of loop, there's a last array with rest of ports which do not make a full 14/15 list
    $outputArray += ,$array

    return $outputArray
}


Function Get-NSXTPortCount {
    param(# Service port array
    [Parameter(ValueFromPipeline = $true, Position = 0, Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript( {$_ -is [array] })]
    [array[]]$InputArray

    $port_count = 0
    foreach ($port in $InputArray){
        if ($port -like "*-*"){
            $port_count +=2
        }
        else{
            $port_count +=1
        }
    }
    return $port_count
}


Function Verify-NSXTFirewallRuleInputData {
    param(
        # Parameter help description
        [Parameter(ValueFromPipeline = $true, Mandatory = $true, HelpMessage = "NSXT Firewall Rule Input Data")]
        [ValidateNotNullorEmpty()]
        [string[]]$InputFWRule,
        # Parameter help description
        [Parameter(ValueFromPipelineByPropertyName = $true, Mandatory = $true, HelpMessage = "NSXT Firewall Rule Input Property")]
        [ValidateNotNullorEmpty()]
        $Property
    )

    ## Get Header name
    $Name = $Property.n
    ## Index and rule count
    $fw_i = 0
    $fw_count = $InputFWRule.Count
    $_fwRules = @()
    $dataAllOK = $true

    Write-Host "`nStart checking FW rule data" -ForegroundColor Yellow
    start-sleep 1

    foreach ($fwrule in $InputFWRule) {

        $fw_i++
        "{0,-70} {1,20}" -f "`tVerifying FW rule: $($fwrule.$($Name[0]))", "# $fw_i out of $fw_count" | out-string | write-host 
        $RuleNameOK = $true
        $RuleSrcIPOK = $true
        $RuleDstIPOK = $true
        $RulePortsOK = $true

        ## Check whether fw name contains special characetors aka nay charactor besides a-z, A-Z, 0-9, "-", "_", and " "
        if ($fwrule.$($Name[0]) -match "[^a-zA-Z0-9-_ ]"){
            Write-host "`t`t Rule Name, $($fwrule.$($Name[0])), contains special charactor(s)" -ForegroundColor Red
            $RuleNameOK = $false
            Start-Sleep 1
        }
        else{
            Write-Host "`t`t Rule Name, $($fwrule.$($Name[0])), is OK without special charactor" -ForegroundColor Green
        }

        ## check source IP addresses
        $sourceIPs = @()
        $sourceIPs += $( $fwrule.$($Name[1]) -replace " ", "" ) -split ";" | where { -not [string]::IsNullOrWhiteSpace($_) }
        $fwrule.$($Name[1]) = $sourceIPs
        foreach ($ip in $sourceIPs){
            if ( !(Verify-IP($ip)) ){
                $RuleSrcIPOK = $false
                Write-Host "`t`t Source IP not correct: $ip" -ForegroundColor red
                start-sleep 1
            }
        }

        if($RuleSrcIPOK){
            Write-Host "`t`t Rule Source IPs are ALL OK!" -ForegroundColor Green
        }

        ## check destination IP addresses
        $destIPs = @()
        $destIPs += $( $fwrule.$($Name[2]) -replace " ", "" ) -split ";" | where { -not [string]::IsNullOrWhiteSpace($_) }
        $fwrule.$($Name[2]) = $destIPs
        foreach ($ip in $destIPs){
            if ( !(Verify-IP($ip)) ){
                $RuleDstIPOK = $false
                Write-Host "`t`t Destination IP not correct: $ip" -ForegroundColor red
                start-sleep 1
            }
        }

        if($RuleDstIPOK){
            Write-Host "`t`t Rule Destination IPs are ALL OK!" -ForegroundColor Green
        }

        ## check rule service ports
        $Ports = @()
        $Ports += $( $fwrule.$($Name[3]) -replace " ", "" ) -split ";" | where { -not [string]::IsNullOrWhiteSpace($_) }
        $fwrule.$($Name[3]) = $Ports

        if ( Verify-Port($ports) ) {
            Write-Host "`t`t Ports format are ALL OK!" -ForegroundColor Green
            Write-Host
        }
        else{
            $RulePortsOK = $false
            Start-Sleep 1
            Write-Host
        }

        ## if any of them is false, set $dataALLOK to false
        if ( !($RuleNameOK -and $RuleSrcIPOK -and $RuleDstIPOK -and $RulePortsOK) ) {
            $dataAllOK = $false
        }

        $_fwRules += $fwrule
    }

    ## if duplicated firewall rule name found
    $duplicatedRuleName = $InputFWRule | Group-Object $($Name[0]) | where {$_.count -ge 2}

    if($duplicatedRuleName){
        Write-Host "`nDuplicated Rule Name found in the input csv file: " -ForegroundColor red -BackgroundColor Yellow
        $duplicatedRuleName.Group | ft -Property $Property | Out-String | Write-Host
        $dataAllOK = $false
        Start-Sleep 1
    }
    else{
        Write-Host "`n`tNo Duplicated rule name found in the input csv file!" -ForegroundColor  Green
    }

    if($dataAllOK){
        return $_fwRules
    }
    else{
        return $dataAllOK
    }

}


Function Get-ExceptionResponse{
    param (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $errorResponse
    )
    $readResponse = New-Object System.IO.StreamReader($errorResponse.Exception.Response.GetResponseStream())
    $body = $readResponse.ReadToEnd()
    Return $body
}

