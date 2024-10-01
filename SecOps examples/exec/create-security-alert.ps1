##
# PowerShell code to parse and generate tickets for REDACTED FAZ SOC IPS alerts

Import-Module /REDACTED/modules/AuthFunctions.psm1
Import-Module /REDACTED/modules/DebugFunctions.psm1
Import-Module /REDACTED/modules/PSAFunctions.psm1

# Creating variable from argument received via FAZ Webhook

$fazpayload=$args

# Parsing JSON to obtain device hostname

$jsonfazpayload1 = $fazpayload | ConvertFrom-Json | Select-Object -ExpandProperty data | Select-Object devname
$jsonfazpayload2 = $fazpayload | ConvertFrom-Json | Select-Object -ExpandProperty data | Select-Object log-detail
$jsonfazpayload3 = $fazpayload | ConvertFrom-Json | Select-Object -ExpandProperty data | Select-Object devid

# Creating variables from device payload parsed

$devicename = $jsonfazpayload1.devname
$logdetail = $jsonfazpayload2
$deviceserial = $jsonfazpayload3.devid

# Establish body for search of service ticket via Connectwise API

$summarystring = "$devicename has flagged a potential security incident"

# Invoke request to GET a Connectwise Manage Service Ticket from previously obtained IDs and variables

SearchManageTicketBySummary -summaryparam $summarystring

# If statement to prevent a new ticket being opened if the search returns a ticket that is already opened

if ($searchticketresult -match 'id') {
    
    $ticketid = $searchticketresult.id

    UpdateManageTicketNotes -ticketidparam $ticketid -textparam $logdetail
    
    Exit
}

# else statement to create a new ticket if the search returns no results

else {
    
    SearchManageCustomerAndSiteByDeviceSerial -deviceserialparam $deviceserial
    CreateManageTicket -summaryparam $summarystring -statusid 1361 -boardid 53 -companyid $devicecompanyid -priorityid 6 -typeid 593 -subtypeid 775 -itemid 447 -siteid $devicelocationid -Content "See log details: $logdetail 
    
    Check https://REDACTED.com, https://REDACTED.sentinelone.net/dashboard, https:/REDACTED.sentinelone.net/dashboard, and https://REDACTED for more details and to review logs further.
    
    See REDACTED internal SOP for additional guidance: https://REDACTED"

}