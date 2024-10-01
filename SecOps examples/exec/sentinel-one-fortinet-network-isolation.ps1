# PowerShell code to parse and perform endpoint isolation via SentinelOne/FortiOS for SOC alerts

Import-Module /REDACTED/modules/AuthFunctions.psm1
Import-Module /REDACTED/modules/DebugFunctions.psm1
Import-Module /REDACTED/modules/PSAFunctions.psm1
Import-Module /REDACTED/modules/S1Functions.psm1
Import-Module /REDACTED/modules/FortiOSFunctions.psm1

# Creating variable from argument received via FAZ Webhook

$fazpayload=$args

# Parsing JSON to obtain device name, serial number, and endpoint IP

$jsonfazpayload1 = $fazpayload | ConvertFrom-Json | Select-Object -ExpandProperty data | Select-Object devname
$jsonfazpayload2 = $fazpayload | ConvertFrom-Json | Select-Object -ExpandProperty data | Select-Object devid
$jsonfazpayload3 = $fazpayload | ConvertFrom-Json | Select-Object -ExpandProperty data | Select-Object epip

# Creating variables from device payload parsed

$devicename = $jsonfazpayload1.devname
$deviceserial = $jsonfazpayload2.devid
$endpointip = $jsonfazpayload3.epip

# Establish request to find customer info for device from Manage PSA API

SearchManageCustomerAndSiteByDeviceSerial -deviceserialparam $deviceserial

# Attempt isolation via S1 API console

if ($devicecompanyname -match 'REDACTED') {
    S1NetworkIsolation -endpointipparam $endpointip -companynameparam $devicecompanyname -consoleurlparam "REDACTED.sentinelone.net" -filteridparam 1680612295329725500
}

elseif ($devicecompanyname -match 'REDACTED') {
    S1NetworkIsolation -endpointipparam $endpointip -companynameparam $devicecompanyname -consoleurlparam "REDACTED.sentinelone.net" -filteridparam 1677226226259228592
}

else {
    S1NetworkIsolation -endpointipparam $endpointip -companynameparam $devicecompanyname -consoleurlparam "REDACTED.sentinelone.net" -filteridparam 1601961462156516439
}

# Attempt isolation via NGFW if endpoint isolation via agent fails

if ($s1isolationresult.data -match 'affected=0') {
    Write-Output "No endpoints found in S1; proceeding with FortiOS IP Ban POST to Ansible"
    
    FortiOSIPBanAnsible -endpointipparam $endpointip -deviceserialparam $deviceserial

    Write-Output "JSON payload POST attempt completed to Ansible for processing"

    SearchManageTicketBySummary -summary "$devicename has flagged a potential security incident"

    $ticketid = $searchticketresult.id
    UpdateManageTicketNotes -ticketidparam $ticketid -textparam "SecOps Automated Action: No endpoint(s) found in S1; attempted FortiOS IP Ban"

}

# Create and update incident ticket with isolation success details

elseif ($s1isolationresult.data -match 'affected=[1-9][0-9]*') {
    Write-Output "Endpoint found in S1; isolation successful"
    
    SearchManageTicketBySummary -summary "$devicename has flagged a potential security incident"

    $ticketid = $searchticketresult.id
    UpdateManageTicketNotes -ticketidparam $ticketid -textparam "SecOps Automated Action: Endpoint(s) found in S1; network isolation successful"

}