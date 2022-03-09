# Author:      Connor Jackson
# Description: PS script designed to parse Microsoft Audit logs into csv format, and perform geoIP lookups.

$csvInput = Import-Csv *auditlog*.csv | select -ExpandProperty AuditData
$table = @{}

$CreationTime = $parsed | Select-Object -Property CreationTime
$ClientIPAddress = $parsed | Select-Object -Property ClientIPAddress
$ClientInfoString = $parsed | Select-Object -Property ClientInfoString
$ExternalAccess = $parsed | Select-Object -Property ExternalAccess
$Id = $parsed | Select-Object -Property Id
$InternalLogonType = $parsed | Select-Object -Property InternalLogonType
$LogonType = $parsed | Select-Object -Property LogonType
$LogonUserSid = $parsed | Select-Object -Property LogonUserSid
$MailboxGuid = $parsed | Select-Object -Property MailboxGuid
$MailboxOwnerSid = $parsed | Select-Object -Property MailboxOwnerSid
$MailboxOwnerUPN = $parsed | Select-Object -Property MailboxOwnerUPN
$Operation = $parsed | Select-Object -Property Operation
$OperationCount = $parsed | Select-Object -Property OperationCount
$OrganizationId = $parsed | Select-Object -Property OrganizationId
$OrganizationName = $parsed | Select-Object -Property OrganizationName
$OriginatingServer = $parsed | Select-Object -Property OriginatingServer
$RecordType = $parsed | Select-Object -Property RecordType
$ResultStatus = $parsed | Select-Object -Property ResultStatus
$SessionId = $parsed | Select-Object -Property SessionId
$UserId = $parsed | Select-Object -Property UserId
$UserKey = $parsed | Select-Object -Property UserKey
$UserType = $parsed | Select-Object -Property UserType
$Version = $parsed | Select-Object -Property Version
$Workload = $parsed | Select-Object -Property Workload

$Folders = $parsed.Folders | Select-Object Folder, Path
$OperationProperties = $parsed.OperationProperties | Select-Object Name, Value
$ExtendedProperties = $parsed.ExtendedProperties | Select-Object Name, Value
$AzureActiveDirectoryEventType = $parsed | Select-Object -Property AzureActiveDirectoryEventType

$parsed = $csvInput | ConvertFrom-Json
#$output = $parsed | Select-Object -Property CreationTime, UserId, ClientIPAddress, ClientInfoString, ExternalAccess, Id, InternalLogonType, LogonType, LogonUserSid, MailboxGuid, MailboxOwnerSid, MailboxOwnerUPN, Operation, OperationCount, OrganizationId, OrganizatioName, OriginatingServer, RecordType, ResultStatus, SessionId, UserType, Version, Workload | Export-Csv out.csv

# Filter IPs to minimize queries
$uniqueIP = $parsed.ClientIPAddress
$uniqueIP = $uniqueIP | sort -Uniq 


# Remove IPv6 info (keeps below API limit)
$v4 = $uniqueIP | where {$_ -notmatch ':'}
Write-Output('Unique IPs Found:')
Write-Output('--------')
$v4

# Perform geolocation on unique IP addresses found
Function GetGeoDetails($ip)
{
    $geoApi = 'http://ip-api.com/json/' + $v4[$i]
    $geoApiRes = Invoke-RestMethod -Method Get -Uri $geoApi
    
    $geoIp = $v4[$i] 
    $geoCountry = $geoApiRes.country
    $geoCity = $geoApiRes.city

    $table.$geoIP = @()
    $table.$geoIP += $geoCountry, $geoCity
    #return $table
}

# Loop through unique IPs and perform geolocation, store into hashtable for lookup
for (($i = 0); $i -lt $v4.Length; $i++)
{
    GetGeoDetails -ip $v4[$i]
}


$table
 
#$parsed = $csvInput | ConvertFrom-Json

for (($i = 0); $i -lt $parsed.Length; $i++)
{
    if ($parsed[$i].ClientIPAddress)
    {
        if ($table.ContainsKey($parsed[$i].ClientIPAddress))
        {
            $r = $parsed[$i].ClientIPAddress
            $parsed[$i] | Add-Member -Name Country -Value $table.$r[0] -MemberType NoteProperty
            $parsed[$i] | Add-Member -Name City -Value $table.$r[1] -MemberType NoteProperty

        }
        else 
        {
            $parsed[$i] | Add-Member -Name Country -Value '' -MemberType NoteProperty
            $parsed[$i] | Add-Member -Name City -Value '' -MemberType NoteProperty
        }
    }

    if ($parsed[$i].ExtendedProperties)
    {
        $r = $parsed[$i].ExtendedProperties 
        $parsed[$i] | Add-Member -Name UserAgent -Value $r[1] -MemberType NoteProperty -Force
        $parsed[$i] | Add-Member -Name RequestType -Value $r[2] -MemberType NoteProperty -Force
        $parsed[$i] | Add-Member -Name ResultStatusDetail -Value $r[3] -MemberType NoteProperty -Force
    }
    else
    {
        $parsed[$i] | Add-Member -Name UserAgent -Value '' -MemberType NoteProperty -Force
        $parsed[$i] | Add-Member -Name RequestType -Value '' -MemberType NoteProperty -Force
        $parsed[$i] | Add-Member -Name ResultStatusDetail -Value '' -MemberType NoteProperty -Force
    }
}



$parsed | export-csv Results.csv
