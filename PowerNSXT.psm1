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



