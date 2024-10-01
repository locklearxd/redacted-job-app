## REDACTED FORTIOS FUNCTIONS TO HANDLE INCIDENT RESPONSE AND MITIGATION ACTIONS AND OTHER TASKS

function FortiOSIPBanAnsible {
    param (
    #Required parameters
    [Parameter(Mandatory=$true)]
    [string]$deviceserialparam,
    [Parameter(Mandatory=$true)]
    [string]$endpointipparam
    )

    process {

    $ansiblebody = @{
        device="$deviceserialparam"
        endpoint="$endpointipparam"
    }
    
    $jsonansiblebody = $ansiblebody | ConvertTo-Json -Depth 4
    
    $ansiblestatuscode = $null
    Invoke-RestMethod -Uri "http://REDACTED:9051/hooks/fortios-ban-ip-hook" -Body $jsonansiblebody -Method Post -ContentType 'application/json' -StatusCodeVariable ansiblestatuscode

    if ( $ansiblestatuscode -ne 200 ) {
        Write-Output 'An Ansible Webhook error has occurred!'; 
        $errorpayload = Get-Error -Newest 1; 
        DevOpsSyslogDebug -Content $errorpayload -Tag "FortiOSIPBanAnsible"; 
        DevOpsLocalLogDebug -Content $errorpayload -Funcname "FortiOSIPBanAnsible"; 
        DevOpsOpenTicketDebug -Content $errorpayload; 
        Exit
    }

    }
}