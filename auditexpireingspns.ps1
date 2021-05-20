Param
(
    [Parameter (Mandatory = $true,
        HelpMessage = "Enter the originating email address.")]
    [string] $FromEmailAddress,
    [Parameter (Mandatory = $true,
        HelpMessage = "Enter the destination email address.")]
    [string] $ToEmailAddress,
    [Parameter (Mandatory = $true,
        HelpMessage = "Enter the email subject.")]
    [string] $EmailSubject,
    [Parameter (Mandatory = $true,
        HelpMessage = "Enter the number of days to warn of credential expiry")]
    [string] $ExpiresInDays
)

function Send-EmailWithSendGrid {
    Param
    (
        [Parameter(Mandatory = $true)]
        [string] $From,

        [Parameter(Mandatory = $true)]
        [String] $To,

        [Parameter(Mandatory = $true)]
        [string] $ApiKey,

        [Parameter(Mandatory = $true)]
        [string] $Subject,

        [Parameter(Mandatory = $true)]
        [string] $Body

    )

    $headers = @{}
    $headers.Add("Authorization", "Bearer $apiKey")
    $headers.Add("Content-Type", "application/json")

    $jsonRequest = [ordered]@{
        personalizations = @(@{to = @(@{email = "$To" })
                subject           = "$SubJect" 
            })
        from             = @{email = "$From" }
        content          = @( @{ type = "text/plain"
                value        = "$Body" 
            }
        )
    } | ConvertTo-Json -Depth 10
    Invoke-RestMethod   -Uri "https://api.sendgrid.com/v3/mail/send" -Method Post -Headers $headers -Body $jsonRequest 

}

try {
    #Get the connection "AzureRunAsConnection "

    $servicePrincipalConnection = Get-AutomationConnection -Name "AzureRunAsConnection"

    "Logging in to Azure..."
    $connectionResult = Connect-AzAccount -Tenant $servicePrincipalConnection.TenantID `
        -ApplicationId $servicePrincipalConnection.ApplicationID   `
        -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint `
        -ServicePrincipal
    "Logged in."

}
catch {
    if (!$servicePrincipalConnection) {
        $ErrorMessage = "Connection $connectionName not found."
        throw $ErrorMessage
    }
    else {
        Write-Error -Message $_.Exception
        throw $_.Exception
    }
}


Write-Host 'Gathering necessary information...'
$applications = Get-AzADApplication
$servicePrincipals = Get-AzADServicePrincipal

$appWithCredentials = @()
$appWithCredentials += $applications | Sort-Object -Property DisplayName | % {
    $application = $_
    $sp = $servicePrincipals | ? ApplicationId -eq $application.ApplicationId
    Write-Verbose ('Fetching information for application {0}' -f $application.DisplayName)
    $application | Get-AzADAppCredential -ErrorAction SilentlyContinue | Select-Object -Property @{Name = 'DisplayName'; Expression = { $application.DisplayName } }, @{Name = 'ObjectId'; Expression = { $application.Id } }, @{Name = 'ApplicationId'; Expression = { $application.ApplicationId } }, @{Name = 'KeyId'; Expression = { $_.KeyId } }, @{Name = 'Type'; Expression = { $_.Type } }, @{Name = 'StartDate'; Expression = { $_.StartDate -as [datetime] } }, @{Name = 'EndDate'; Expression = { $_.EndDate -as [datetime] } }
}

Write-Host 'Validating expiration data...'
$today = (Get-Date).ToUniversalTime()
$limitDate = $today.AddDays($ExpiresInDays)
$appWithCredentials | Sort-Object EndDate | % {
    if ($_.EndDate -lt $today) {
        $_ | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'Expired'
    }
    elseif ($_.EndDate -le $limitDate) {
        $_ | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'ExpiringSoon'
    }
    else {
        $_ | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'Valid'
    }
}

$ExpiringAppCredentials = $appWithCredentials | ? { $_.Status -eq 'Expired' -or $_.Status -eq 'ExpiringSoon' } | Sort-Object -Property DisplayName
$ExpiringAppCredentialsString = $ExpiringAppCredentials | Out-String
#$ExpiringAppCredentialsString = $ExpiringAppCredentials | sort-object -Property enddate | format-table  -Property displayname, startdate, enddate, status, applicationid, keyid, type | Out-String


$ApiKeyString = Get-AutomationVariable -Name "SendGridAutomationCloudServices"

$From = $FromEmailAddress 
$To = $ToEmailAddress  
$APIKEY = $ApiKeyString
$Subject = $EmailSubject 
$Body = "$ExpiringAppCredentialsString"

Send-EmailWithSendGrid -from $from -to $to -ApiKey $APIKEY -Body $Body -Subject $Subject
