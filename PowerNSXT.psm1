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

Function Select-File {
    param(
        [Parameter(ValueFromPipeline = $true, HelpMessage = "Enter CSV Path(s)")]
        [string[]]$file_path = $null,
        [string[]]$titleMesg,
        [string]$Type = "CSV File(s)|*.csv"
    )

    Write-Host "A window will prompt up on your primary monitor, asking to select a file" -ForegroundColor Yellow
    
    if(!$file_path) {
        add-type -AssemblyName System.Windows.Forms
        $current_dir = Get-Location
        $Dialog = New-Object System.Windows.Forms.OpenFileDialog
        $Dialog.InitialDirectory  = $current_dir.Path
        $Dialog.Title = $titleMesg
        #$Dialog.Filter  = "CSV File(s)|*.csv"
        $Dialog.Filter  = $Type
        $Dialog.Multiselect = $false
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
    )

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


Function Get-NSXTDomain {
    
    param (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true, HelpMessage = "NSX-T Server FQDN or IP ")]
        [ValidateNotNullOrEmpty()]
        $nsxtServer,
        # Parameter help description
        [Parameter(ValueFromPipeline = $true, Mandatory = $true, HelpMessage  = "NSX-T credential")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript( {$_ -is [PSCredential] } )]
        [PSCredential]$cred
    )

    $baseURL = "https://$nsxtServer/policy/api/v1/infra"
    $URI = "/domains?include_mark_for_delete_objects=false&page_size=1000&sort_ascending=true"
    $FullURI = $baseURL + $URI
    $method = "get"
    $Timeout= 600
    $username = $cred.GetNetworkCredential().UserName
    $password = $cred.GetNetworkCredential().Password 
    $base64Cred = [system.convert]::ToBase64String( [System.Text.Encoding]::UTF8.GetBytes("${username}:${password}") )
    $headerDictionary = @{"Authorization" = "Basic $base64Cred"}

    ## Use splatting to build up the IRM params
    $irmSplat = @{
        "method" = $method
        "headers" = $headerDictionary
        "ContentType" = "application/json"
        "uri" = $FullURI
        "TimeoutSec" = $Timeout
    }

    ## skip certificate verification to support self signed certificate
    ## not supported by PowerShell 5 or lower
    if($PSVersionTable.PSVersion.Major -ge 6){
        $irmSplat.add("SkipCertificateCheck", $true)
    }

    try {
        $response = invoke-webrequest @irmSplat -ErrorAction:Stop
    }
    Catch [System.Net.WebException] {
        Write-Host "`tError in getting NSX-T Domains" -ForegroundColor Red
        $response = Get-ExceptionResponse($_)
        Write-Host $response -ForegroundColor Yellow
        exit(1)
    }

    if($response.StatusCode -eq 200) {
        $response = $response.content | ConvertFrom-Json
    }

    return $response
}


Function Get-NSXTSecurityPolicy {

    param (
        [Parameter(ValueFromPipeline = $true, Mandatory= $true, HelpMessage = "NSX-T Server FQDN or IP")]
            [validateNotNullorEmpty()]
            [string]$nsxtServer,
        [Parameter(ValueFromPipeline = $false, Mandatory= $true, HelpMessage = "NSX-T credential")]
            [validateNotNullorEmpty()]
            [ValidateScript({$_ -is [PSCredential]})]
            [PSCredential]$cred,
        # Parameter help description
        [Parameter(ValueFromPipeline = $false, Mandatory = $false)]
            [ValidateNotNullorEmpty()]
            [string]$DomainID = "default",
        # Parameter help description
        [Parameter(ValueFromPipeline = $false, Mandatory = $false)]
            [ValidateNotNullorEmpty()]
            [ValidateScript({$_ -is [string]})]
            [string]$ID
        )

        $baseURL = "https://$nsxtServer/policy/api/v1/infra"

        if( $PSBoundParameters.ContainsKey('ID')){
            $URI = "/domains/$DomainID/security-policies/$ID"
        }
        else{
            $URI = "/domains/$DomainID/security-policies?include_rule_count=true&sort_ascending=true"
        }

        $FullURI = $baseURL + $URI
        $method = "get"
        $Timeout= 600
        $username = $cred.GetNetworkCredential().UserName
        $password = $cred.GetNetworkCredential().Password 
        $base64Cred = [system.convert]::ToBase64String( [System.Text.Encoding]::UTF8.GetBytes("${username}:${password}") )
        $headerDictionary = @{"Authorization" = "Basic $base64Cred"}

        ## Use splatting to build up the IRM params
        $irmSplat = @{
            "method" = $method
            "headers" = $headerDictionary
            "ContentType" = "application/json"
            "uri" = $FullURI
            "TimeoutSec" = $Timeout
        }
    
        ## skip certificate verification to support self signed certificate
        ## not supported by PowerShell 5 or lower
        if($PSVersionTable.PSVersion.Major -ge 6){
            $irmSplat.add("SkipCertificateCheck", $true)
        }
    
        try {
            $response = invoke-webrequest @irmSplat -ErrorAction:Stop
        }
        Catch [System.Net.WebException] {
            Write-Host "`tError in getting NSX-T security policy" -ForegroundColor Red
            $response = Get-ExceptionResponse($_)
            Write-Host $response -ForegroundColor Yellow
            exit(1)
        }
    
        if($response.StatusCode -eq 200) {
            $response = $response.content | ConvertFrom-Json
        }
        
        ## API call result is different
        ## To get Muliple security policy needs to use $response.results
        if ($PSBoundParameters.ContainsKey('ID') ){
            return $response
        }
        else{
            return $response.results
        }
    
}


Function Set-NSXTSecurityPolicy {

    param (
        [Parameter(ValueFromPipeline = $true, Mandatory= $true, HelpMessage = "NSX-T Server FQDN or IP")]
            [validateNotNullorEmpty()]
            [string]$nsxtServer,
        [Parameter(ValueFromPipeline = $false, Mandatory= $true, HelpMessage = "NSX-T credential")]
            [validateNotNullorEmpty()]
            [ValidateScript({$_ -is [PSCredential]})]
            [PSCredential]$cred,
        # Parameter help description
        [Parameter(ValueFromPipeline = $false, Mandatory = $false)]
            [ValidateNotNullorEmpty()]
            [string]$DomainID = "default",
        # Parameter help description
        [Parameter(ValueFromPipeline = $false, Mandatory = $true)]
            [ValidateNotNullorEmpty()]
            [ValidateScript({$_ -is [string]})]
            [string]$ID,
        [Parameter(ValueFromPipeline = $false, Mandatory = $true)]
            [ValidateNotNullorEmpty()]
            $body
        )

        $baseURL = "https://$nsxtServer/policy/api/v1/infra"
        $URI = "/domains/$DomainID/security-policies/$ID"
        $FullURI = $baseURL + $URI
        $method = "Put"
        $Timeout= 600
        $username = $cred.GetNetworkCredential().UserName
        $password = $cred.GetNetworkCredential().Password 
        $base64Cred = [system.convert]::ToBase64String( [System.Text.Encoding]::UTF8.GetBytes("${username}:${password}") )
        $headerDictionary = @{"Authorization" = "Basic $base64Cred"}

        ## Use splatting to build up the IRM params
        $irmSplat = @{
            "method" = $method
            "headers" = $headerDictionary
            "ContentType" = "application/json"
            "uri" = $FullURI
            "TimeoutSec" = $Timeout
        }
        
        ## skip certificate verification to support self signed certificate
        ## not supported by PowerShell 5 or lower
        if($PSVersionTable.PSVersion.Major -ge 6){
            $irmSplat.add("SkipCertificateCheck", $true)
        }

        $irmSplat.add('body',$body)

        try {
            $response = invoke-webrequest @irmSplat -ErrorAction:Stop
        }
        Catch [System.Net.WebException] {
            Write-Host "`tError in setting NSX-T security policy" -ForegroundColor Red
            $response = Get-ExceptionResponse($_)
            Write-Host $response -ForegroundColor Yellow
            exit(1)
        }
    
        if($response.StatusCode -eq 200) {
            Write-Host "Security policy $ID updated successfully!" -ForegroundColor Green
            $response = $response.content | ConvertFrom-Json
        }
        
        ## API call result is different
        ## To get Muliple security policy needs to use $response.results
        if ($PSBoundParameters.ContainsKey('ID') ){
            return $response
        }
        else{
            return $response.results
        }    
}

Function Get-NSXTService {

    param (
        [Parameter(ValueFromPipeline = $true, Mandatory= $true, HelpMessage = "NSX-T Server FQDN or IP")]
            [validateNotNullorEmpty()]
            [string]$nsxtServer,
        [Parameter(ValueFromPipeline = $false, Mandatory= $true, HelpMessage = "NSX-T credential")]
            [validateNotNullorEmpty()]
            [ValidateScript({$_ -is [PSCredential]})]
            [PSCredential]$cred,
        # Parameter help description
        [Parameter(ValueFromPipeline = $false, Mandatory = $false)]
            [ValidateNotNullorEmpty()]
            [ValidateScript({$_ -is [string]})]
            [string]$ID
        )

        $baseURL = "https://$nsxtServer/policy/api/v1/infra"

        if( $PSBoundParameters.ContainsKey('ID')){
            $URI = "/services/$ID"
        }
        else{
            $URI = "/services?sort_ascending=true"
        }

        $FullURI = $baseURL + $URI
        $method = "get"
        $Timeout= 600
        $username = $cred.GetNetworkCredential().UserName
        $password = $cred.GetNetworkCredential().Password 
        $base64Cred = [system.convert]::ToBase64String( [System.Text.Encoding]::UTF8.GetBytes("${username}:${password}") )
        $headerDictionary = @{"Authorization" = "Basic $base64Cred"}

        ## Use splatting to build up the IRM params
        $irmSplat = @{
            "method" = $method
            "headers" = $headerDictionary
            "ContentType" = "application/json"
            "uri" = $FullURI
            "TimeoutSec" = $Timeout
        }
    
        ## skip certificate verification to support self signed certificate
        ## not supported by PowerShell 5 or lower
        if($PSVersionTable.PSVersion.Major -ge 6){
            $irmSplat.add("SkipCertificateCheck", $true)
        }
    
        try {
            $response = invoke-webrequest @irmSplat -ErrorAction:Stop
        }
        Catch [System.Net.WebException] {
            Write-Host "`tError in getting NSX-T service" -ForegroundColor Red
            $response = Get-ExceptionResponse($_)
            Write-Host $response -ForegroundColor Yellow
            exit(1)
        }
    
        if($response.StatusCode -eq 200) {
            $response = $response.content | ConvertFrom-Json
        }
        
        ## API call result is different
        ## To get Muliple services needs to use $response.results
        if ($PSBoundParameters.ContainsKey('ID') ){
            return $response
        }
        else{
            return $response.results
        }
    
}

Function New-NSXTService {

    param (
        [Parameter(ValueFromPipeline = $false, Mandatory= $true, HelpMessage = "NSX-T Server FQDN or IP")]
            [validateNotNullorEmpty()]
            [string]$nsxtServer,
        [Parameter(ValueFromPipeline = $false, Mandatory= $true, HelpMessage = "NSX-T credential")]
            [validateNotNullorEmpty()]
            [ValidateScript({$_ -is [PSCredential]})]
            [PSCredential]$cred,
        # Parameter help description
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
            [ValidateNotNullorEmpty()]
            [string]$Name,
        # Parameter help description
        [Parameter(ValueFromPipelineByPropertyName = $true, Mandatory = $true)]
            [ValidateNotNullorEmpty()]
            [string[]]$Ports,
        [Parameter(ValueFromPipeline = $false, Mandatory = $false)]
            [switch]$debugging
        )

        $serviceEntry_List = @()
        ## NSX-T/v each service entry can only have maximum 15 ports; port range counts as 2
        [int]$serviceEntry_portNumLimit = 15
        $tcpPorts = @()
        $udpPorts = @()
        $tcpPorts += ($ports | where {$_ -match "^tcp"}) -replace "tcp", ""
        $udpPorts += ($Ports | where {$_ -match "^udp"}) -replace "udp", ""

        if($tcpPorts){
            $tcpPorts_count = Get-NSXTPortCount($tcpPorts)
            if($tcpPorts_count -gt $serviceEntry_portNumLimit) {
                $tcpPorts = Split-NSXTPorts -InputArray $tcpPorts -SubArraySize $serviceEntry_portNumLimit
                for($i=1; $i -le $tcpPorts.count; $i++){
                    $serviceEntry = @{
                        display_name = $Name + "-TCP-" + $i
                        resource_type = "L4PortSetServiceEntry"
                        destination_ports = $tcpPorts[$i-1]
                        l4_protocol  = "TCP"
                    }
                    $serviceEntry_List += $serviceEntry
                }
            }
            else {
                $serviceEntry = @{
                    display_name = $Name + "-TCP-1"
                    resource_type = "L4PortSetServiceEntry"
                    destination_ports = $tcpPorts
                    l4_protocol  = "TCP"
                }
                $serviceEntry_List += $serviceEntry
            }
        }

        if($udpPorts){
            $udpPorts_count = Get-NSXTPortCount($udpPorts)
            if($udpPorts_count -gt $serviceEntry_portNumLimit) {
                $udpPorts = Split-NSXTPorts -InputArray $udpPorts -SubArraySize $serviceEntry_portNumLimit
                for($i=1; $i -le $udpPorts.count; $i++){
                    $serviceEntry = @{
                        display_name = $Name + "-UDP-" + $i
                        resource_type = "L4PortSetServiceEntry"
                        destination_ports = $udpPorts[$i-1]
                        l4_protocol  = "UDP"
                    }
                    $serviceEntry_List += $serviceEntry
                }
            }
            else {
                $serviceEntry = @{
                    display_name = $Name + "-UDP-1"
                    resource_type = "L4PortSetServiceEntry"
                    destination_ports = $udpPorts
                    l4_protocol  = "UDP"
                }
                $serviceEntry_List += $serviceEntry
            }
        }

        $body = @{
            display_name = $Name
            service_entries = $serviceEntry_List
        }
        $body = $body | ConvertTo-Json -Depth 6
        if($debugging){
            Write-Host "New service config:"
            Write-host $body
        }

        $baseURL = "https://$nsxtServer/policy/api/v1/infra"
        $URI = "/services/$Name"
        $FullURI = $baseURL + $URI
        $method = "patch"
        $Timeout= 600
        $username = $cred.GetNetworkCredential().UserName
        $password = $cred.GetNetworkCredential().Password 
        $base64Cred = [system.convert]::ToBase64String( [System.Text.Encoding]::UTF8.GetBytes("${username}:${password}") )
        $headerDictionary = @{"Authorization" = "Basic $base64Cred"}

        ## Use splatting to build up the IRM params
        $irmSplat = @{
            "method" = $method
            "headers" = $headerDictionary
            "ContentType" = "application/json"
            "uri" = $FullURI
            "TimeoutSec" = $Timeout
        }
        
        ## skip certificate verification to support self signed certificate
        ## not supported by PowerShell 5 or lower
        if($PSVersionTable.PSVersion.Major -ge 6){
            $irmSplat.add("SkipCertificateCheck", $true)
        }

        $irmSplat.add('body',$body)

        try {
            $response = invoke-webrequest @irmSplat -ErrorAction:Stop
        }
        Catch [System.Net.WebException] {
            Write-Host "`tError in creating NSX-T service" -ForegroundColor Red
            $response = Get-ExceptionResponse($_)
            Write-Host $response -ForegroundColor Yellow
            exit
        }
    
        if($response.StatusCode -eq 200) {
            Write-Host "`tSuccessfully created new NSX-T Service $Name!" -ForegroundColor Green
            $response = $response.content | ConvertFrom-Json
        }

        return $response
}


Function Set-NSXTService {

    param(
    [Parameter (ValueFromPipeline = $true, Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $ID,
    [Parameter (ValueFromPipeline = $true, Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $Ports,
    [Parameter (ValueFromPipeline = $true, Mandatory=$true, HelpMessage = "NSXT server FQDN or IP")]
        [ValidateNotNullOrEmpty()]
        $nsxtServer,
    [Parameter (ValueFromPipeline = $false, Mandatory=$true, HelpMessage = "NSX-T credential")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript( {$_ -is [PSCredential]} )]
        [PSCredential]$cred,
    [Parameter (ValueFromPipeline= $false, Mandatory= $false)]
        [switch]$debugging
    )
    
    $Service = Get-NSXTService -ID $ID -NsxTServer $nsxtServer -cred $cred
    
    if(!($Service)){
        Write-Host "Service ID $ID not found" -ForegroundColor Red
        exit
    }
    
    $Name = $ID
    
    $serviceEntry_List = @()
    
    # NSX-T one service entry can only have maximum 15 individual port
    [int]$serviceEntry_portNumLimit = 15
    $tcpPorts =@()
    $udpPorts = @()
    $tcpPorts += ($ports | where {$_ -match "^tcp"}) -replace "tcp", ""
    $udpPorts += ($Ports | where {$_ -match "^udp"}) -replace "udp", ""
    
    if($tcpPorts){
        $tcpPorts_count = Get-NSXTPortCount($tcpPorts)
        if($tcpPorts_count -gt $serviceEntry_portNumLimit) {
            $tcpPorts = Split-NSXTPorts -InputArray $tcpPorts -SubArraySize $serviceEntry_portNumLimit
            for($i=1; $i -le $tcpPorts.count; $i++){
                $serviceEntry = @{
                    display_name = $Name + "-TCP-" + $i
                    resource_type = "L4PortSetServiceEntry"
                    destination_ports = $tcpPorts[$i-1]
                    l4_protocol  = "TCP"
                }
                $serviceEntry_List += $serviceEntry
            }
        }
        else {
            $serviceEntry = @{
                display_name = $Name + "-TCP-1"
                resource_type = "L4PortSetServiceEntry"
                destination_ports = $tcpPorts
                l4_protocol  = "TCP"
            }
            $serviceEntry_List += $serviceEntry
        }
    }

    if($udpPorts){
        $udpPorts_count = Get-NSXTPortCount($udpPorts)
        if($udpPorts_count -gt $serviceEntry_portNumLimit) {
            $udpPorts = Split-NSXTPorts -InputArray $udpPorts -SubArraySize $serviceEntry_portNumLimit
            for($i=1; $i -le $udpPorts.count; $i++){
                $serviceEntry = @{
                    display_name = $Name + "-UDP-" + $i
                    resource_type = "L4PortSetServiceEntry"
                    destination_ports = $udpPorts[$i-1]
                    l4_protocol  = "UDP"
                }
                $serviceEntry_List += $serviceEntry
            }
        }
        else {
            $serviceEntry = @{
                display_name = $Name + "-UDP-1"
                resource_type = "L4PortSetServiceEntry"
                destination_ports = $udpPorts
                l4_protocol  = "UDP"
            }
            $serviceEntry_List += $serviceEntry
        }
    }
    $oldServiceEntry_Count = $Service.service_entries.count
    $newServiceEntry_Count = $serviceEntry_List.Count
    
    ## if new service entry count equal or larger than old service entry count
    ## update all old service entry
    ## then add the extra service entry if any
    
    if($newServiceEntry_Count -ge $oldServiceEntry_Count) {
        ## Update old service entries
        for($i=0; $i -lt $oldServiceEntry_Count; $i++){
            $Service.service_entries[$i].display_name = $serviceEntry_List[$i].display_name
            $Service.service_entries[$i].l4_protocol = $serviceEntry_List[$i].l4_protocol
            $Service.service_entries[$i].resource_type = $serviceEntry_List[$i].resource_type
            $Service.service_entries[$i].destination_ports = $serviceEntry_List[$i].destination_ports
        }
        
        ## if new service entry count is higher than old, add extra entry to old service, from 
        if ($newServiceEntry_Count -gt $oldServiceEntry_Count) {
            foreach ($entry in $serviceEntry_List[$oldServiceEntry_Count..$($newServiceEntry_Count - 1)]) {
                $Service.service_entries += $entry
            }
        }
    }
    
    ## if new service entry count less than old service entry count 
    ## update the old service's corresponding entries; and remove extra ones
    if($newServiceEntry_Count -lt $oldServiceEntry_Count) {
        $tempServiceEntry_List = @()
        for($i=0; $i -lt $newServiceEntry_Count; $i++){
            $Service.service_entries[$i].display_name = $serviceEntry_List[$i].display_name
            $Service.service_entries[$i].l4_protocol = $serviceEntry_List[$i].l4_protocol
            $Service.service_entries[$i].resource_type = $serviceEntry_List[$i].resource_type
            $Service.service_entries[$i].destination_ports = $serviceEntry_List[$i].destination_ports
            $tempServiceEntry_List += $Service.service_entries[$i]
        }
        #remove extra entries
        $Service.service_entries= $tempServiceEntry_List
    }
    
    
    $baseURL = "https://$nsxtServer/policy/api/v1/infra"
    $URI = "/services/$ID"
    $FullURI = $baseURL + $URI
    $method = "patch"
    $Timeout= 600
    $username = $cred.GetNetworkCredential().UserName
    $password = $cred.GetNetworkCredential().Password 
    $base64Cred = [system.convert]::ToBase64String( [System.Text.Encoding]::UTF8.GetBytes("${username}:${password}") )
    $headerDictionary = @{"Authorization" = "Basic $base64Cred"}

    ## Use splatting to build up the IRM params
    $irmSplat = @{
        "method" = $method
        "headers" = $headerDictionary
        "ContentType" = "application/json"
        "uri" = $FullURI
        "TimeoutSec" = $Timeout
    }
    
    ## skip certificate verification to support self signed certificate
    ## not supported by PowerShell 5 or lower
    if($PSVersionTable.PSVersion.Major -ge 6){
        $irmSplat.add("SkipCertificateCheck", $true)
    }

    $body = $Service | ConvertTo-Json -Depth 6
    $irmSplat.add('body',$body)
    if($debugging){
        Write-Host "New service config:"
        Write-Host $body
    }

    try {
        $response = invoke-webrequest @irmSplat -ErrorAction:Stop
    }
    Catch [System.Net.WebException] {
        Write-Host "`tError in updating NSX-T service" -ForegroundColor Red
        $response = Get-ExceptionResponse($_)
        Write-Host $response -ForegroundColor Yellow
        exit
    }

    if($response.StatusCode -eq 200) {
        Write-Host "`tSuccessfully updated new NSX-T Service $Name!" -ForegroundColor Green
        $response = $response.content | ConvertFrom-Json
    }

    return $response
}


Function Remove-NSXTService {

    param(
        [Parameter (ValueFromPipeline = $true, Mandatory=$true, ParameterSetName = 'ID')]
            [ValidateNotNullOrEmpty()]
            $ID,
        [Parameter (ValueFromPipeline = $true, Mandatory=$true, ParameterSetName = 'Name')]
            [ValidateNotNullOrEmpty()]
            $Name,
        [Parameter (ValueFromPipeline = $true, Mandatory=$true, HelpMessage = "NSXT server FQDN or IP")]
            [ValidateNotNullOrEmpty()]
            $nsxtServer,
        [Parameter (ValueFromPipeline = $false, Mandatory=$true, HelpMessage = "NSX-T credential")]
            [ValidateNotNullOrEmpty()]
            [ValidateScript( {$_ -is [PSCredential]} )]
            [PSCredential]$cred
    )
    
    If ($PSBoundParameters.ContainsKey('ID')) {
        $Service = Get-NSXTService -ID $ID -NsxTServer $nsxtServer -cred $cred
        if(!($Service)){
            Write-Host "Service ID $ID not found" -ForegroundColor Red
            exit
        }
    }
    
    ## Normally, service should not have duplicated display name
    If ($PSBoundParameters.ContainsKey('Name')) {
        $Service = Get-NSXTService | where {$_.display_name -like $Name}
        if(!($Service)){
            Write-Host "Service $Name not found" -ForegroundColor Red
            exit
        }
    }    
    
    $baseURL = "https://$nsxtServer/policy/api/v1/infra"
    $URI = "/services/$($Service.ID)"
    $FullURI = $baseURL + $URI
    $method = "DELETE"
    $Timeout= 600
    $username = $cred.GetNetworkCredential().UserName
    $password = $cred.GetNetworkCredential().Password 
    $base64Cred = [system.convert]::ToBase64String( [System.Text.Encoding]::UTF8.GetBytes("${username}:${password}") )
    $headerDictionary = @{"Authorization" = "Basic $base64Cred"}

    ## Use splatting to build up the IRM params
    $irmSplat = @{
        "method" = $method
        "headers" = $headerDictionary
        "ContentType" = "application/json"
        "uri" = $FullURI
        "TimeoutSec" = $Timeout
    }
    
    ## skip certificate verification to support self signed certificate
    ## not supported by PowerShell 5 or lower
    if($PSVersionTable.PSVersion.Major -ge 6){
        $irmSplat.add("SkipCertificateCheck", $true)
    }


    try {
        $response = invoke-webrequest @irmSplat -ErrorAction:Stop
    }
    Catch [System.Net.WebException] {
        Write-Host "`tError in deleting NSX-T service $($Service.ID)" -ForegroundColor Red
        $response = Get-ExceptionResponse($_)
        Write-Host $response -ForegroundColor Yellow
        Return $false
        exit
    }

    if($response.StatusCode -eq 200) {
        Write-Host "`tSuccessfully deleted new NSX-T Service $($Service.ID)" -ForegroundColor Green
        return $true
    }
}

Function New-NSXTFWRuleBODY {

    param(
        # Parameter help description
        [Parameter (ValueFromPipeline = $true, Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            $Name,
        [Parameter (ValueFromPipeline = $false, Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [string[]]$SrcIP, 
        [Parameter (ValueFromPipeline = $false, Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [string[]]$DstIP, 
        [Parameter (ValueFromPipeline = $false, Mandatory=$false)]
            [ValidateNotNullOrEmpty()]
            [sting[]]$port,
        [Parameter (ValueFromPipeline = $false, Mandatory=$false)]
            [string]$notes="",
        [Parameter (ValueFromPipeline = $false, Mandatory=$false)]
            [ValidateNotNullOrEmpty()]
            [string[]]$svc,
        [Parameter (ValueFromPipeline= $false, Mandatory=$false)]
            [ValidateNotNullOrEmpty()]
            [ValidateScript( {$_ -is [int]} )]
            [int]$SequenceNumber=0
    )
    
    $_rule_body = get-content $PSscriptRoot\nsxt_fwrule_template.json | ConvertFrom-Json
    $_rule_body.id = $Name
    $_rule_body.display_name = $Name
    $_rule_body.sequence_number = $SequenceNumber
    $_rule_body.source_groups += $SrcIP
    $_rule_body.destination_groups += $DstIP
    $_rule_body.notes = $notes
    $_rule_body.services += $svc

    return $_rule_body
}

Function Get-NSXTFirewallRule {
    # Parameter help description
    param(
        [Parameter (ValueFromPipeline = $true, Mandatory=$true, HelpMessage = "NSXT server FQDN or IP")]
            [ValidateNotNullOrEmpty()]
            $nsxtServer,
        [Parameter (ValueFromPipeline = $false, Mandatory=$true, HelpMessage = "NSX-T credential")]
            [ValidateNotNullOrEmpty()]
            [ValidateScript( {$_ -is [PSCredential]} )]
            [PSCredential]$cred,
        [Parameter (ValueFromPipeline = $false, Mandatory=$false)]
            [ValidateNotNullOrEmpty()]
            $DomainID = "default",
        [Parameter (ValueFromPipeline = $false, Mandatory=$false)]
            [ValidateNotNullOrEmpty()]
            $SecurityPolicyID,
        [Parameter (ValueFromPipeline = $false, Mandatory=$false, ParameterSetName = 'RuleID')]
            [ValidateNotNullOrEmpty()]
            $RuleID,
        [Parameter (ValueFromPipeline = $false, Mandatory=$false, ParameterSetName = 'RuleName')]
            [ValidateNotNullOrEmpty()]
            $RuleName
    )
    $FWRules = @()

    if ( $PSBoundParameters.containsKey('SecurityPolicyID')) {
        $FWRules += (Get-NSXTSecurityPolicy -nsxtServer $nsxtServer -cred $cred -ID $SecurityPolicyID).rules
    }else {
        ## retrive all security policy list and the get rules from each policy
        $securityPolices = Get-NSXTSecurityPolicy -nsxtServer $nsxtServer -cred $cred 
        foreach ($securityPolicy in $securityPolices){
            $FWRules += (Get-NSXTSecurityPolicy -nsxtServer $nsxtServer -cred $cred -ID $securityPolicy.ID ).rules
        }
    }

    if($PSBoundParameters.ContainsKey('RuleID')){
        $FWRules = $FWRules | where {$_.ID -like $RuleID}
        if($FWRules){
            return $FWRules
        }
        else{
            Write-Host "`tNo NSX-T Firewall rules with ID $RuleID Found" -ForegroundColor Red
            return $false
        }
    }

    if($PSBoundParameters.ContainsKey('RuleName')){
        $FWRules = $FWRules | where {$_.display_name -like $RuleName}
        if($FWRules){
            return $FWRules
        }
        else{
            Write-Host "`tNo NSX-T Firewall rules with name $RuleName Found" -ForegroundColor Red
            return $false
        }
    }


}
    

Function Set-logfile {
    # Get Time Stamp
    $global:timestamp= Get-Date -format "yyyy-MM-dd_HH_mm"
    # Set Path Values
    $LogPath = "$PSscriptRoot\logs"
    If (!(test-path $LogPath)) {
        mkdir $LogPath | out-null
    }
    
    $logfile = (Get-Item $PSCommandPath).BaseName + "_" + $global:timestamp + ".log"

    return "$LogPath\$logfile"
}
# $exportFunctionList = 'Select-NSXTServer', 'Select-File', 'Confirm-File', 'Verify-IP', 'Verify-Port', 'Split-NSXTPorts', 'Get-NSXTPortCount', 'Verify-NSXTFirewallRuleInputData', 'Get-ExceptionResponse', 'Get-ExceptionResponse', 'Get-NSXTDomain'
# Export-ModuleMember -Function $exportFunctionList 