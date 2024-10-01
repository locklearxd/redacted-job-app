## DEBUG FUNCTIONS TO HANDLE ERRORS AND ASSIST DEVELOPMENT

function DevOpsSyslogDebug {

#This function is used to send debug and error information to a syslog server. It is default parameters to send to the REDACTED FortiAnalyzer server.

param (
    # Default parameters
    $IP = "REDACTED",
    $Facility = "local7",
    $Severity = "notice",
    $SourceHostname = "REDACTED-DC-SECOPS",
    $Tag = "PowerShell",
    $Port = 514,
    
    # The content parameter can be any string
    [Parameter(Mandatory=$true)]
    [string]$Content
    )

Process {

 switch -regex ($Facility)
 {
 'kern' {$Facility = 0 * 8 ; break } 
 'user' {$Facility = 1 * 8 ; break }
 'mail' {$Facility = 2 * 8 ; break }
 'system' {$Facility = 3 * 8 ; break }
 'auth' {$Facility = 4 * 8 ; break }
 'syslog' {$Facility = 5 * 8 ; break }
 'lpr' {$Facility = 6 * 8 ; break }
 'news' {$Facility = 7 * 8 ; break }
 'uucp' {$Facility = 8 * 8 ; break }
 'cron' {$Facility = 9 * 8 ; break }
 'authpriv' {$Facility = 10 * 8 ; break }
 'ftp' {$Facility = 11 * 8 ; break }
 'ntp' {$Facility = 12 * 8 ; break }
 'logaudit' {$Facility = 13 * 8 ; break }
 'logalert' {$Facility = 14 * 8 ; break }
 'clock' {$Facility = 15 * 8 ; break }
 'local0' {$Facility = 16 * 8 ; break }
 'local1' {$Facility = 17 * 8 ; break }
 'local2' {$Facility = 18 * 8 ; break } 
 'local3' {$Facility = 19 * 8 ; break }
 'local4' {$Facility = 20 * 8 ; break }
 'local5' {$Facility = 21 * 8 ; break }
 'local6' {$Facility = 22 * 8 ; break }
 'local7' {$Facility = 23 * 8 ; break }
 default {$Facility = 23 * 8 } #Default is local7
 }

 switch -regex ($Severity)
 { 
 '^em' {$Severity = 0 ; break } #Emergency 
 '^a' {$Severity = 1 ; break } #Alert
 '^c' {$Severity = 2 ; break } #Critical
 '^er' {$Severity = 3 ; break } #Error
 '^w' {$Severity = 4 ; break } #Warning
 '^n' {$Severity = 5 ; break } #Notice
 '^i' {$Severity = 6 ; break } #Informational
 '^d' {$Severity = 7 ; break } #Debug
 default {$Severity = 5 } #Default is Notice
 }

$pri = "<" + ($Facility + $Severity) + ">"

 if ($(get-date).day -lt 10) { $timestamp = $(get-date).tostring("MMM d HH:mm:ss") } else { $timestamp = $(get-date).tostring("MMM dd HH:mm:ss") }

# Hostname does not have to be in lowercase, and it shouldn't have spaces anyway, but lowercase is more traditional.

 $header = $timestamp + " " + $sourcehostname.tolower().replace(" ","").trim() + " "

# Cannot have non-alphanumerics in the TAG field or have it be longer than 32 characters. 
 if ($tag -match '[^a-z0-9]') { $tag = $tag -replace '[^a-z0-9]','' } #Simply delete the non-alphanumerics
 if ($tag.length -gt 32) { $tag = $tag.substring(0,31) } #and truncate at 32 characters.

$msg = $pri + $header + $tag + ": " + $content

# Convert message to array of ASCII bytes.
 $bytearray = $([System.Text.Encoding]::ASCII).getbytes($msg)

# RFC3164 Section 4.1: "The total length of the packet MUST be 1024 bytes or less."
 # "Packet" is not "PRI + HEADER + MSG", and IP header = 20, UDP header = 8, hence:
 if ($bytearray.count -gt 996) { $bytearray = $bytearray[0..995] }

# Send the message... 
 $UdpClient = New-Object System.Net.Sockets.UdpClient 
 $UdpClient.Connect($IP,$Port) 
 $UdpClient.Send($ByteArray, $ByteArray.length) | out-null
}

}

function DevOpsLocalLogDebug {

    #This function is used to log debug and error information to a local file. It will either create a new file or append to an existing file.

    param (
        [Parameter(Mandatory=$true)]
        [string]$Funcname,
        # The content parameter can be any string
        [Parameter(Mandatory=$true)]
        [string]$Content
        )

    Process {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logentry = "$timestamp - $Funcname - $Content"
        Add-Content -Path /REDACTED/logs/devops-debug.log -Value $logentry
    }

}

function DevOpsOpenTicketDebug {

    #This function is used to open a ticket in ConnectWise Manage for debugging and development purposes. It will either create a new ticket or update an existing ticket with the same summary to prevent ticket spam.

    param (
        # Default parameters
        # The content parameter can be any string
        [Parameter(Mandatory=$true)]
        [string]$Content
        )

    Process {

    ManageAuthentication
    
    SearchManageTicketBySummary -summaryparam "DevOps Debug Ticket Alert" -debugsuccess $true
    
    if ($searchticketresult -match 'id') {
    
    $ticketid = $searchticketresult.id

    UpdateManageTicketNotes -ticketidparam $ticketid -textparam $Content -debugsuccess $true
    }
    
    else {
    CreateManageTicket -summaryparam "DevOps Debug Ticket Alert" -statusid 1360 -boardid 53 -companyid 250 -priorityid 8 -typeid 593 -subtypeid 775 -itemid 447 -siteid $devicelocationid -Content $Content -debugsuccess $true -resourceparam "aharter"
    }

    }
}

Export-ModuleMember -Function DevOpsDebug, DevOpsSyslogDebug, DevOpsLocalLogDebug, DevOpsOpenTicketDebug