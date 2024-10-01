## S1 FUNCTIONS TO HANDLE INCIDENT RESPONSE AND MITIGATION ACTIONS AND OTHER TASKS

function S1NetworkIsolation {
    param (
        #Required parameters
        [Parameter(Mandatory=$true)]
        [string]$endpointipparam,
        [Parameter(Mandatory=$true)]
        [string]$companynameparam,
        [Parameter(Mandatory=$true)]
        [string]$consoleurlparam,
        [Parameter(Mandatory=$true)]
        [string]$filteridparam
    )
    
    process {

    $functionname = $MyInvocation.MyCommand.Name

    SentinelOneAuthentication
    
    if ( $consoleurlparam -match 'REDACTED.sentinelone.net' ) {
        
        $sentinelonecompanyinfo = Invoke-RestMethod -Uri https://REDACTED.sentinelone.net/web/api/v2.1/sites?name__contains=$companynameparam -Method Get -Headers $sentineloneclientauthheaders -ContentType application/json
        $sentinelonecompanyid = $sentinelonecompanyinfo | ConvertTo-Json -Depth 8 | ConvertFrom-Json | Select-Object -ExpandProperty data | Select-Object -ExpandProperty sites | Select-Object id
        
        $sentinelonebody1 = @{ filter= @{filterId=$filteridparam; networkInterfaceInet__contains=$endpointipparam; filteredSiteIds=$sentinelonecompanyid.id } }
        $sentinelonebody2 = @{ filter= @{filterId=$filteridparam; networkInterfaceInet__contains=$endpointipparam; filteredSiteIds=$sentinelonecompanyid.id }; data= @{message="This computer has been disconnected from the network due to a security risk. Please contact REDACTED at REDACTED for assistance. Our team has been notified."} }
        
        $jsonsentinelonebody1 = $sentinelonebody1 | ConvertTo-Json
        $jsonsentinelonebody2 = $sentinelonebody2 | ConvertTo-Json

        # Notify user and isolate endpoint via S1; if isolation fails on lookup, proceed with network IP ban

        $global:s1broadcastresult = Invoke-RestMethod -Uri "https://REDACTED.sentinelone.net/web/api/v2.1/agents/actions/broadcast" -Method Post -Headers $sentineloneclientauthheaders -Body $jsonsentinelonebody2

        $global:s1isolationresult = Invoke-RestMethod -Uri "https://REDACTED.sentinelone.net/web/api/v2.1/agents/actions/disconnect" -Method Post -Headers $sentineloneclientauthheaders -Body $jsonsentinelonebody1

    }

    elseif ( $consoleurlparam -match 'REDACTED.sentinelone.net' ) {
            
        $sentinelonecompanyinfo = Invoke-RestMethod -Uri https://REDACTED.sentinelone.net/web/api/v2.1/sites?name__contains=$companynameparam -Method Get -Headers $sentineloneREDACTEDauthheaders -ContentType application/json
        $sentinelonecompanyid = $sentinelonecompanyinfo | ConvertTo-Json -Depth 8 | ConvertFrom-Json | Select-Object -ExpandProperty data | Select-Object -ExpandProperty sites | Select-Object id
            
        $sentinelonebody1 = @{ filter= @{filterId=$filteridparam; networkInterfaceInet__contains=$endpointipparam; filteredSiteIds=$sentinelonecompanyid.id } }
        $sentinelonebody2 = @{ filter= @{filterId=$filteridparam; networkInterfaceInet__contains=$endpointipparam; filteredSiteIds=$sentinelonecompanyid.id }; data= @{message="This computer has been disconnected from the network due to a security risk. Please contact REDACTED at REDACTED for assistance. Our team has been notified."} }
            
        $jsonsentinelonebody1 = $sentinelonebody1 | ConvertTo-Json
        $jsonsentinelonebody2 = $sentinelonebody2 | ConvertTo-Json
    
        # Notify user and isolate endpoint via S1; if isolation fails on lookup, proceed with network IP ban
    
        $global:s1broadcastresult = Invoke-RestMethod -Uri "https://REDACTED.sentinelone.net/web/api/v2.1/agents/actions/broadcast" -Method Post -Headers $sentineloneREDACTEDauthheaders -Body $jsonsentinelonebody2
    
        $global:s1isolationresult = Invoke-RestMethod -Uri "https://REDACTED.sentinelone.net/web/api/v2.1/agents/actions/disconnect" -Method Post -Headers $sentineloneREDACTEDauthheaders -Body $jsonsentinelonebody1

    }

    else {
        Write-Output "No valid SentinelOne console URL provided! Exiting!";
        $errorpayload = "No valid SentinelOne console URL provided! Exiting!"; 
        DevOpsSyslogDebug -Content $errorpayload -Tag "SentinelOneNetworkIsolation"; 
        DevOpsLocalLogDebug -Content $errorpayload -Funcname $functionname;
        Exit
    }

}
}

function S1BadAgentLookup {
REDACTED
        
REDACTED
    else {
        Write-Output "No valid SentinelOne console URL provided! Exiting!"
        $errorpayload = "No valid SentinelOne console URL provided! Exiting!"; 
        DevOpsSyslogDebug -Content $errorpayload -Tag "S1BadAgentLookup"; 
        DevOpsLocalLogDebug -Content $errorpayload -Funcname $functionname; 
        Exit
    }

}

function S1ThreatLookup {
    param (
        #Required parameters
        [Parameter(Mandatory=$true)]
        [string]$consoleurlparam
    )

    process {

    $functionname = $MyInvocation.MyCommand.Name

    SentinelOneAuthentication

    if ( $consoleurlparam -match 'REDACTED.sentinelone.net') {
    
    $threatlist = Invoke-RestMethod -Uri "https://REDACTED.sentinelone.net/web/api/v2.1/threats?confidenceLevels=malicious&incidentStatuses=unresolved" -Method Get -Headers $sentineloneclientauthheaders -ContentType application/json

    $dataexpanded = $threatlist | Select-Object -ExpandProperty data

        foreach ( $threat in $dataexpanded ) {

        $threatinfo = $threat.threatInfo
        $agentinfo = $threat | Select-Object -ExpandProperty agentRealtimeinfo
        
        $threatpath = $threatinfo.filePath
        $threatname = $threatinfo.threatName
        $agentid = $agentinfo.agentId
        $devicename = $agentinfo.agentComputerName
        $devicecompanyname = $agentinfo.siteName
    
        SearchManageTicketBySummary -summary "$devicename via S1 has flagged a potential security incident"

        if ($searchticketresult -match 'id') {
            Write-Output "A ticket already exists"
        }

        else {
        
        $companyNamesToExclude = @("REDACTED", "Example Company B")

        # Check if the company name is in the array of company names to exclude
        if ($companyNamesToExclude -contains $devicecompanyname) {
        Write-Output "Skipping loop item because company name $devicecompanyname is in the array of company names to exclude"
        continue
        }

        $s1agentinfo = Invoke-RestMethod -Uri "https://REDACTED.sentinelone.net/web/api/v2.1/agents?ids=$agentid" -Headers $sentineloneclientauthheaders -ContentType application/json

        $s1agentserial = $s1agentinfo.data | Select-Object -ExpandProperty serialNumber

        SearchManageDeviceWithSerialAndHostname -devicehostnameparam $devicename -deviceserialparam $s1agentserial
        SearchManageCustomerByCustomerName -customernameparam $devicecompanyname
        CreateManageTicket -summaryparam "$devicename via S1 has flagged a potential security incident" -statusid 1361 -boardid 53 -companyid $devicecompanyid -priorityid 6 -typeid 602 -subtypeid 795 -itemid 460 -siteid $devicelocationid -content "See threat name and path details: $threatname detected at: $threatpath
    
        Check https://REDACTED, https://REDACTED.sentinelone.net/dashboard, and https://REDACTED for more details and to review logs further.
        
        See internal SOP for additional guidance: https://REDACTED"

        }

    }

    }

    elseif ( $consoleurlparam -match 'REDACTED.sentinelone.net') {

    $threatlist = Invoke-RestMethod -Uri "https://REDACTED.sentinelone.net/web/api/v2.1/threats?confidenceLevels=malicious&incidentStatuses=unresolved" -Method Get -Headers $sentineloneREDACTEDauthheaders -ContentType application/json

    $dataexpanded = $threatlist | Select-Object -ExpandProperty data

        foreach ( $threat in $dataexpanded ) {

        $threatinfo = $threat.threatInfo
        $agentinfo = $threat | Select-Object -ExpandProperty agentRealtimeinfo

        $threatpath = $threatinfo.filePath
        $threatname = $threatinfo.threatName
        $agentid = $agentinfo.agentId
        $devicename = $agentinfo.agentComputerName
        $devicecompanyname = $agentinfo.siteName

        SearchManageTicketBySummary -summary "$devicename via S1 has flagged a potential security incident"

        if ($searchticketresult -match 'id') {
            Write-Output "A ticket already exists"
        }

        else {
        
        $s1agentinfo = Invoke-RestMethod -Uri "https://REDACTED.sentinelone.net/web/api/v2.1/agents?ids=$agentid" -Headers $sentineloneREDACTEDauthheaders -ContentType application/json

        s1agentserial = $s1agentinfo.data | Select-Object -ExpandProperty serialNumber

        SearchManageDeviceWithSerialAndHostname -devicehostnameparam $devicename -deviceserialparam $s1agentserial
        SearchManageCustomerByCustomerName -customernameparam $devicecompanyname
        CreateManageTicket -summaryparam "$devicename via S1 has flagged a potential security incident" -statusid 1361 -boardid 53 -companyid $devicecompanyid -priorityid 6 -typeid 602 -subtypeid 795 -itemid 460 -siteid $devicelocationid -content "See threat name and path details: $threatname detected at: $threatpath
    
        Check https://REDACTED, https://REDACTED.sentinelone.net/dashboard, and https://REDACTED for more details and to review logs further.
        
        See internal SOP for additional guidance: https://REDACTED"

    }

}

    }

    else {
    Write-Output "No valid SentinelOne console URL provided! Exiting!"
    $errorpayload = "No valid SentinelOne console URL provided! Exiting!"; 
    DevOpsSyslogDebug -Content $errorpayload -Tag "SentinelOneThreatLookup"; 
    DevOpsLocalLogDebug -Content $errorpayload -Funcname $functionname; 
    Exit
    }

    }
}

Export-ModuleMember -Function S1NetworkIsolation, S1BadAgentLookup, S1ThreatLookup