Import-Module PowerNSXT
$OutputLogLocation = Set-logfile
Start-Transcript -path $outputLogLocation -Append

## Check nsx-t server json file
if(!$(test-path "$PSscriptRoot\NSXT_Servers.json")){
    write-host "NSXT_Servers.json file is missing. Please check!" -ForegroundColor red -BackgroundColor Yellow 
    exit 
}
# Check nsx-t firewall rule template json file
if(!$(test-path "$PSscriptRoot\nsxt_fwrule_template.json") ) {
    write-host "nsxt_fwrule_template.json file is missing. Please check!" -ForegroundColor red -BackgroundColor Yellow
    exit 
}
else{
    $nsxt_fwrule_template = get-content $PSscriptRoot\nsxt_fwrule_template.json | convertfrom-json 
}

$dummy_class = @'
using System;
using System.Net;
using System.Net.Security; using System.Security.Cryptography.X509Certificates;

public static class Dummy {
    public static bool ReturnTrue(object sender,
        X509Certificate certificate, 
        X509Chain chain,
        SslPolicyErrors sslPolicy Errors) { return true; }

    public static RemoteCertificateValidationCallback GetDelegate() {
        return new RemoteCertificateValidationCallback(Dummy. Return True);
    }
} 
'@

## ignore self signed SSL certificate for powershell 5 and lower version
if ($PSVersionTable.PSVersion.Major -le 5) {
    if (-not("dummy" -as [type])) {
        add-type -TypeDefinition $dummy_class
    }
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [dummy]::GetDelegate()
}

## define input csv headaer and output format
$Property = @(
    @{n="Name"; e={$_.Name}; Width=30},
    @{n="SrcIP"; e={$_.SrcIP}; width=30},
    @{n="DstIP"; e={$_.DstIP}; Width=30},
    @{n="Ports"; e={$_.Ports}; width=30}, 
    @{n="Section"; e={$_.Section}; width=30},
    @{n="Notes"; e={$_.notes}; width=30}
)

## select input firewall rule csv file and confirm
$confirmInputFile = $false
while (!$confirmInputFile){
    $inputcsv = import-csv (Select-File -titlemesg "Please select a NSXT firewall input CSV file")
    $confirmInputFile = Confirm-file -inputfile $inputcsv -Property $Property
}

## Verify input data
$VerifiedInputData = Verify-NSXTFirewallRuleInputData -InPutFWRule $inputcsv -property $Property
if(!$VerifiedInputData) {
    write-host "`n`n"
    write-host ("#"*60) -ForegroundColor Yellow
    Write-host "Data has issues. Please correct it and re-run the script!" -foregroundcolor red -BackgroundColor Yellow
    write-host ("#"*60) -ForegroundColor Yellow
    break
}
else{
    write-host "`n`n"
    write-host ("#"*60) -ForegroundColor Yellow
    Write-host "All data verified without issues. Proceed to the next step!" -ForegroundColor Green
    write-host ("#"*60) -ForegroundColor Yellow
}
## $Name_prefix = read-host -prompt "Please enter the prefix for FW Name and service Name"
$Name_prefix  = "PA-"

## select nsx-t server and enter credential
$nsxt = select-nsxtServer

$nsxtcred = $null
While (!($nsxtcred)){
    $nsxtcred = Get-Credential -Message "Please enter NSX-T Administrative Credentials: "

    ## verify credential by Checking domain and getting domain ID: default
    Write-Host "Verifying credential and Retriving NSX-T Infrastructure Domain information"
    $NSXTDomains = Get-NSXTDomain -NsxTServer $nsxt -cred $nsxtCred
    switch ($NSXTDomains.result_count) {
        ($null) {
            write-host "`nInvalid user name or password. Please re-enter your credential" -foregroundcolor red -BackgroundColor yellow
            $nsxtcred = $null
            start-sleep 2
        }
        (0) {
                write-host "`nValid credential but can't find any NSXT Infrastruture Domain" -foregroundcolor red -BackgroundColor yellow;
                exit
        }
        (1) {
            Write-host "`nValid credential. 1 NSX-T Infrastructure Domain: $($NSXTDomains.results[0].id) Found" -foregroundcolor green;
            $DomainID = $NSXTDomains.results[0].id 
        }
        default {
            Write-host "`nValid credential. Found more than one NSX-T Infrastructure Domain. This script doesn't support." -foregroundcolor red -BackgroundColor yellow;
            exit
        }
    }
}

## check whether sections from csv file all exist in the nsxt environment
## if not, exit script
$sections=@()
$sections += $inputcsv.$($Property.n[4]) | sort | get-unique
$sect_count = $sections.count
Write-host "`nThere are $sect_count sections from the Input file" -foregroundcolor green
$sections | ft | out-string | Write-Host
Write-host "Verifying whether those sections from csv file exist in NSX-T" -ForegroundColor green
$NSXTAllSP = Get-NSXTSecurityPolicy -NsxTServer $nsxt -cred $nsxtCred -DomainID $DomainID 
Write-host "`nSections exist in NSX-T:" -ForegroundColor green
write-host ("#"*60) -ForegroundColor yellow
$NSXTAllSP | sort category| select resource_type, display_name, category, sequence_number | ft | out-string | Write-Host

$allSectionsExist = $true
foreach ($section in $sections) {
    $target_sect = $NSXTAllSP | where {$_.display_name -like $section}
    if(!$target_sect){
        $allSectionsExist = $false 
        write-host ("#"*60)
        Write-host "Section $section doesn't exist in $nsxt. Please correct your input file!" -BackgroundColor yellow -foregroundcolor red
        write-host ("#"*60)
    }
}

if (!$allSectionsExist){
    write-host ("#"*60) -ForegroundColor Yellow
    Write-host "Please check your input file and re-run the script!" -foregroundcolor red -BackgroundColor yellow
    write-host ("#"*60) -ForegroundColor yellow
    break
}
else{
    write-host ("#"*60) -ForegroundColor yellow
    Write-host "All sections from input file exist in NSX-T; proceed to the next step" -foregroundcolor green
    write-host ("#"*60) -ForegroundColor yellow
    }

$sect_i=0
$allNSXTServices = Get-NSXTService -NsxTServer $nsxt -cred $nsxtCred
$ServiceRemoveList = @() 
foreach ($section in $sections) {
    $sect_i++
    "{0,-50} {1, 20}" -f "`nProcessing section: $section", "# $sect_i out of $sect_count" | write-host -foregroundcolor Yellow
    ## find the targe security policy for the full list and get its id 
    ## Firewall section is called security policy in NSX-T
    $target_sect = $NSXTAllSP | where {$_.display_name -like $section} 
    $sectionID = $target_sect.id
    ## $NSXTAllSP only contains basic section infor without rule details
    ## use the target security policy id to retrieve the full information with firewall rules in the section
    $target_sect = Get-NSXTSecurityPolicy -NsxTServer $nsxt -cred $nsxtCred -DomainID $DomainID -ID $sectionID 

    ## Back up the security policy before making any change for recovery purpose
    $backupfileName = $nsxt + "_" + $target_sect.display_name + "_backup_" + $global:timestamp + ".json"
    $target_sect | convertto-json -Depth 6 | set-content $PSscriptRoot\$backupfileName

    ## if the section is not empty, get the sequence number of the last rule;
    ## else set the number to 0
    if ($target_sect.rules){
        $SN_MAX = $target_sect.rules[-1].sequence_number
    }
    else {
        $SN_MAX = 0
    }

    ## loop through each rule in the same section from the CSV file
    $fwrules = $VerifiedInputData | where {$_.$($Property.n[4]) -like $section}
    $fwrule_count = $fwrules.count 
    $fwrule_i = 0
    foreach ($fwrule in $fwrules) {
        $fwrule_i++
        "{0,-50} {1, 20}" -f "`tProcessing rule: $( $fwrule.$($Property.n[0]) )", "# $fwrule_i out of $fwrule_count" | write-host -foregroundcolor green
        ## define all property variable for the rule
        ## by default, NSX-T increase sequence number by 10 while adding new rule
        $SN_MAX += 10
        $_fwrule_SN = $SN_MAX
        $_fwrule_Name = $Name_prefix + $fwrule.$($Property.n[0])
        $_fwrule_SrcIP = $fwrule.$($Property.n[1])
        $_fwrule_DstIP = $furule.$($Property.n[2])
        $_fwrule_ports = $fwrule.$($Property.n[3])
        $_fwrule_notes = $fwrule.$($Property.n[5]) 
        $_fwrule_svcName = "SP-" + $_fwrule_Name 

        ## Deal with services:
        ## if "any" exists, only use Any
        ## else if "icmp" exists, add ICMP-ALL
        ## if matching tcp|udp, checking whether service already exists, if not, create it; if yes, merge the new ports to service
        $_fwrule_services = @()
        if ($_fwrule_ports -match "any") {
            $_fwrule_services =@("ANY")
        }
        else {
            if ($_fwrule_ports -match "icmp") {
                $_fwrule_services += "/infra/services/ICMP-ALL"
            }

            $_fwrule_l4protocolPorts = @()
            $_fwrule_l4protocolPorts += $_fwrule_ports -match "tcp|udp"
            if ($_fwrule_l4protocolPorts) {
                ## if services do not exist, create it; otherwise, update it
                if( $allNSXTServices.display_name -notcontains $_fwrule_svcName) {
                    Write-host "`t`tService: $_fwrule_svcName not found; creating..."
                    $newService = ""
                    $newService = New-NSXTService -Name $_fwrule_svcName -ports $_fwrule_l4protocolPorts -NsxTServer $nsxt -cred $nsxtCred
                    $_fwrule_services += $newService.path
                }else {
                    Write-host "t'tService: $_fwrule_svcName found; updating..." -foregroundcolor yellow
                    $oldService = @()
                    $oldService += $allNSXTServices | where {$_.display_name -like $_fwrule_svcName}

                    if ($oldService.count -gt 1){
                        Write-Host "More than 1 service with name $_fwrule_svcName found" -ForegroundColor Red
                        exit
                    }
                    else{
                        $oldService = Set-NSXTService -ID $oldService.ID -ports $_fwrule_l4protocolPorts -NsxTServer $nsxt -cred $nsxtCred
                        $_fwrule_services += $oldService.path
                    }
                }
            }
            else{
                ## no tcp|udp port in the rule and no service found
                if( $allNSXTServices.display_name -notcontains $_fwrule_svcName) {
                    Write-host "No udp/tcp ports in the rule; no service $_fwrule_svcName found; skip creating the service entity"
                }

                ## no tcp|upd port in the csv rule but service found
                if( $allNSXTServices.display_name -contains $_fwrule_svcName) {
                    Write-host "`t`tService: $_fwrule_svcName found; but there is no udp/tcp ports in the updated rule"
                    Write-host "`t`tWill delete the service after the rule's updated`n" -foregroundcolor yellow 
                    $ServiceRemoveList += $_fwrule_svcName
                }
            }
        }

        ## Deal with fw rules
        ## if rule does not exist, create it;
        ## if rule exists, update it with new data
        if ($target_sect.rules.display_name -notcontains $_fwrule_Name ){
            Write-host "`t`tRule: $_fwrule_Name not found in section $section; working to add it to the section"
            $_fwrule_new = New-NSXTFWRuleBODY -Name $_fwrule_Name -srcIP $_fwrule_SrcIP -DstIP $_fwrule_DstIP -SVC $_fwrule_services -sequenceNumber $_fwrule_SN -notes $_fwrule_notes
            $target_sect.rules += $_fwrule_new
            Write-host "`t`tRule: $_fwrule_Name added to the config of section $section`n"

        }
        else{
            Write-host "`t`tRule: $_fwrule_Name found in section $section; updating..."
            $_fwrule_old = $target_sect.rules | where {$_.display_name -like $_fwrule_Name}

            if ($_fwrule_old.count -gt 1){
                Write-error "More than 1 rule with name $_fwrule_Name found"
                exit
            }
            else{
                ## get the rule's index in the section
                $rule_index = [array]::indexof($target_sect.rules.id, $_fwrule_old.id)
                # set source_groups/destination_groups/services to empty array to remove old IPs, and then add new IPS to it
                $target_sect.rules[$rule_index].source_groups  = @()
                $target_sect.rules[$rule_index].source_groups += $_fwrule_SrcIP

                $target_sect.rules[$rule_index].destination_groups = @()
                $target_sect.rules[$rule_index].destination_groups += $_fwrule_DstIP

                $target_sect.rules[$rule_index].services = @()
                $target_sect.rules[$rule_index].services += $_fwrule_services

                $target_sect.rules[$rule_index].notes = $_fwrule_notes
                Write-host "`t`tRule: $_fwrule_Name updated in section $section's configuration" -foregroundcolor Green
            }
        }
    }

    if($target_sect){
        write-host "`nPushing config to DFW for section $section" -ForegroundColor Yellow 
        $target_sect_body = $target_sect | convertto-json -Depth 6 
        Set-NSXTSecurityPolicy -ID $sectionID -DomainID $DomainID -NsxTServer $nsxt -cred $nsxtCred -body $target_sect_body
    }
}

## service can only be removed when no rule is using it. 
## that's why only after rules are updated, and those services are no longer needed, we start to remove it
if ($ServiceRemoveList) {
    Write-host "Start to remove services that are no more needed" -foregroundcolor green
    $removeService_Count = $ServiceRemoveList.count
    $removeService_i = 0
    foreach ($removeService in $ServiceRemoveList) {
        $removeService_i++
        "{0,-60} {1, 20}" -f "`nRemoving service: $removeService", "# $removeService_i out of $removeService_Count" | Write-Host -foregroundcolor Yellow
        Remove-NSXTService -ID $removeService -NsxTServer $nsxt -cred $nsxtCred
    }
}

Stop-transcript