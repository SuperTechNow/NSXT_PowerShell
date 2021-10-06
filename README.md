# PowerNSXT
If you come from NSX-v era, you must be familiar with PowerNSX module. 

I myself have been using PowerNSX for couple years and I like it very much. It doesn't only make it very efficient to retrieve information, troubleshoot, and automate build/implementation, but also makes it a lot of fun. 

Over the past couple years, I've built quite some automation scripts that I took pride in for various projects at work using PowerNSX. 

I've always wanted to do something for NSX-T. So here we are. 

This repo is to create a similar module for NSX-T using NSX-T policy API.

I will start with creating some functions for NSX-T Firewall rule creation first. 

# Functions for firewall rule creation/update
Verify-IP:
    This function is used for verifying IP in the proper XXX.XXX.XXX.XXX/YY format, where XXX is between 0-255, and YY is between 0-32
    You can run it like Verify-IP("10.1.1.1") or Verify-IP -ip "10.1.1.1", or Verify-IP -ip "10.1.1.1","10.1.1.2", "10.1.1.3" for multiple IPs.
    The function returns True if the IP address format are all correct, otherwise returns false.

Verify-Port:
    This function is for verifying service ports in input csv file have correct format, like single port tcp22 or udp53, or tcp22-1100 for port range. The number should not exceed 65535.
    The function returns True if port format is correct, otherwise False.

Split-NSXTPorts:
    This function is to split multiple service ports into an array. Each member of the array is a collection of ports for one service entry. Each service entry could only have 15 ports. A port range counts as 2.

Get-NSXTPortCount:
    This function is to calculate the service port count for an array, including single port and port range. 

Verify-NSXTFirewallRuleInputData:
    This function is to verify the csv input data for firewall rule creation/update. It checks rule name, source/destination IPs, service ports, and section (security policy).
    Need to add check against existing rule names in the future.

Get-NSXTDomain:
    This function is to retrieve NSX-T infrastructure domain information. It's used to verify NSX-T credentials.

Get-ExceptionResponse:
    This function is to handle API call exception. 

Get-NSXTSecurityPolicy:
    This function is to retrieve a specific security policy if security policy is provided. Otherwise, it retrieves all security policy. 

Set-NSXTSecurityPolicy:
    This function is to update existing security policy. Security policy ID is required. 

Get-NSXTService:
    This function is to retrieve a specific service if service ID is provided. Otherwise, it retrieves all service entity.

New-NSXTService:
    This function is to create a new service.

Set-NSXTService:
    This function is to update an existing service

Remove-NSXTService:
    This function is to delete an existing service. An unique service ID or service name is required. 

New-NSXTFWRuleBODY:
    This function is to composite a firewall rule body using template json file.

Get-NSXTFirewallRule:
    This function is to retrieve a specific firewall rule if rule ID or rule name is provided. Otherwise it retrieves all firewall rules from all security policies. 

Set-logfile:
    This function is to set up log file for running script.

Select-NSXTServer:
    This function is to select target NSX-T server from json file.

Select-File:
    This function is to let you choose a file from GUI instead of typing the absolute file directory. You can specify what type of file you're looking for by using option -Type. The default type is CSV.

Confirm-File:
    This function is to output the file to powershell console and give user the opportunity to confirm. 


# Script for NSX-T firewall rule creation/update
Under Scripts folder, there several files:
1. NSXT-Firewall-Update.ps1:
    Main script for FW rule creation/update. The script will take in a csv file with firewall rule data with rule name, source/destination IPs, service ports, security policy name and rule notes, validate all data format, then create necessary service entities for rules, compose firewall rule body, add them to a target security policy. After finishing adding all rules from the csv file to a target security policy, it then push the security policy to NSX-T server. The original security policy configuration will be backed up first. 

    So you can update/create hundreds of firewall rules in one security policy through one publishing operation. It avoids massive NSX resync, reduce impact greatly and dramatically increases fw rule creation/update efficiency.

2. Firewall_Rule_Example.csv:
    This is the example of rule input csv file.  The FW rule name should be unique as it will be used as rule ID in NSX-T by default. Service-Now request ticket number is highly recommended to be used as the FW rule name.
    service port should be either single udpxxxxx or tcpxxxxx. or tcpxxxxx-xxxxx|udpxxxxx-xxxxx for port range.

3. NSXT_Servers.json:
    Json file for the list of your target NSX-T servers

4. nsxt_fwrule_template.json:
    Json file for NSX-T firewall rule template

