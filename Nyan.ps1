# Nyanalyzer - An AzureAD users' activities analyzer
# Version: 1.0 @ 06/07/2020
# Tri Bui @ Ferris State University
#
# Usage: ./nyanalyzer.ps1 <input file OR a single email> [number of log samples] [-f] [-debug]
# The script accepts up to 4 parameters
# The first one is required: could be a list of emails in file, or a single email or an inline list of users "user1, user2"
# The second one is optional: define the number of log sample you want to analyze
# -f: force the script to get logs from the last 90 days
# -debug: debug mode

param(
    [Parameter()]
    [string]$username,
    [Parameter()]
    [int]$samples = $null,
    [Parameter()]
    [switch]$f
    )

if ($PSBoundParameters['Debug']) {
    $DebugPreference = 'Continue'
    $isDebug = $true
}

function printNyan {
Clear-Host
Write-Host "
Hi! I'm Nyan, a cat-analyzer - Meow!!" -ForegroundColor Yellow
Write-Host "
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▄▀▒▒▒▒▒▒▒▒▒▒▒▒▄▒▒▒▒▒▒▒▀▄▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒" -ForegroundColor Black -BackgroundColor Gray
Write-Host "▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒" -NoNewline -ForegroundColor DarkRed -BackgroundColor Black 
    Write-Host "█▒▒▄▒▒▒▒▄▒▒▒▒▒▒▒▒▒▒▒▒▒▒█▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒" -ForegroundColor Black -BackgroundColor Gray
Write-Host "▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒" -NoNewline -ForegroundColor Red -BackgroundColor Black 
    Write-Host "█▒▒▒▒▒▒▒▒▒▒▒▒▄█▄▄▒▒▄▒▒▒█▒▄▄▄▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒" -ForegroundColor Black -BackgroundColor Gray
Write-Host "▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒" -NoNewline -ForegroundColor DarkYellow -BackgroundColor Black 
    Write-Host "▄▄▄▄▄▒▒█▒▒▒▒▒▒▀▒▒▒▒▀█▒▒▀▄▒▒▒▒▒█▀▀▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒" -ForegroundColor Black -BackgroundColor Gray
Write-Host "▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒" -NoNewline -ForegroundColor Yellow -BackgroundColor Black 
    Write-Host "██▄▀██▄█▒▒▒▄▒▒▒▒▒▒▒██▒▒▒▒▀▀▀▀▀▒▒▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒" -ForegroundColor Black -BackgroundColor Gray
Write-Host "▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒" -NoNewline -ForegroundColor Cyan -BackgroundColor Black 
    Write-Host "▀██▄▀██▒▒▒▒▒▒▒▒▀▒██▀▒▒▒▒▒▒▒▒▒▒▒▒▒▀██▒▒▒▒▒▒▒▒▒▒▒▒▒▒" -ForegroundColor Black -BackgroundColor Gray
Write-Host "▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒" -NoNewline -ForegroundColor Blue -BackgroundColor Black 
    Write-Host "▀████▒▀▒▒▒▒▄▒▒▒██▒▒▒▄█▒▒▒▒▄▒▄█▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒"  -ForegroundColor Black -BackgroundColor Gray
Write-Host "▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒" -NoNewline -ForegroundColor DarkBlue -BackgroundColor Black 
    Write-Host "▀█▒▒▒▒▄▒▒▒▒▒██▒▒▒▒▄▒▒▒▄▒▒▄▒▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▄█▄▒▒▒▒▒▒▒▒▒▒▒▀▄▒▒▀▀▀▀▀▀▀▀▒▒▄▀▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒█▀▀█████████▀▀▀▀████████████▀▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒████▀▒▒███▀▒▒▒▒▒▒▀███▒▒▀██▀▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
" -ForegroundColor Black -BackgroundColor Gray 
#Write-Host "#########################################################################################################"
}

#########################################################################################################
$thisVersion = "v1.0"

# Check admin privilege
$isRunAsAdministrator = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

# Default number of log samples
if(-not($samples)) { $samples = 100 }

# If user has insufficient logs, treat them all as risk
$forceRisk = 10

# Domain name to append to the username
$domain = "@ferris.edu"

# Enable LocalAD: fetch intomation from LocalAD, this would slow the scripts down signnificantly
# Set to false to use AzureAD, this may not get the users' group and correct password reset time
# Could user Get-MsolUser as an alternative
$LocalADOn = $true

# Enable AuditLogs analyze
$AuditLogOn = $false

# Number of the most frequent access IP (within the same State) to deem as "safe" (baseIP)
$safeIP = 2

# Extended range of the baseDevices, base on the most used Client App
$extend = $true

# Country hop threshold - how many different countries from the logs to trigger the compromised flag
$HopsLimit = 2

# Include MFA logs from the risk logs
$inMFA = $true

# API token for IP service (ipinfo.io) # Free account has 50,000 queries/month
#$IPTOKEN = ""
# API token for proxy detection (ip2location.com) # Free account has 500 queries/month for PX2 package
$VPNTOKEN = ""

# File name settings
$ReportFile = "Nyan-Analyzing-Results_" + (Get-Date).tostring("MM-dd-yyyy") + ".html"
$MonitorFile = "Nyan-Monitoring-Users.csv"
$CompFile = "Nyan-Compromised-Users.csv"
$credsFile = ".\creds.xml"

# IP Proxy table
$ProxyTableFile = ".\ProxyTable.xml"
if (Test-Path $ProxyTableFile -PathType Leaf) {
    $ProxyTable = Import-Clixml $ProxyTableFile
} else { $ProxyTable = @{} }

# IP to country table
$IPTableFile = ".\IPLocation.xml"
if (Test-Path $IPTableFile -PathType Leaf) {
    $IPTable = Import-Clixml $IPTableFile
} else { $IPTable = @{} }

$v6Table = @{}
$v6RegEx = "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
$emailRegEx = "[a-zA-Z0-9!#$%*+\-/?^_`.{|}~]+@([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,4}"

$StartDate = (GET-DATE)

# Define blacklist/whitelist
#$BadProtocols = @("IMAP4","Authenticated SMTP","POP3")
$WhiteApps = @("Exchange ActiveSync")
$WhiteIP = "^161\.57\.([1-9]?\d|[12]\d\d)\.([1-9]?\d|[12]\d\d)$"
$badErrorCode = @("50053","50126")

# List of active groups
$activeGroups = @("Users","Current")

#########################################################################################################
# Sending mail settings
$sendMail = $false
$silentMail = $false

$mailfrom = "" 
$mailto = @("")
$mailcc = @("") 
$mailSub = "Nyan Analyzing Results " + (Get-Date).tostring("MM-dd-yyyy")
$mailBody = "Nyan Analyzing Results for " + (Get-Date).tostring("MM-dd-yyyy")
$mailfiles = @($ReportFile,$MonitorFile,$CompFile)
$mailserver = ""

$mailconf = @{
    From = $mailfrom 
    To = $mailto 
    Subject = $mailSub 
    Body = $mailBody 
    SmtpServer = $mailserver
    Attachments = $mailfiles
}
if($mailcc) { $mailconf.Add("Cc",$mailcc) }

#########################################################################################################


# Check if AzureAD module and creds file exist, then connect to AzureAD
# Auto install AzureAD module if missing
function goAzureAD {
param(
    [Parameter()]
    [string]$credsFile = ".\creds.xml"
    )

    ###############################################################
    # This section requires Admin privilege
        $AzureCheck = Get-Module -ListAvailable -Name AzureAdPreview
        $EXOCheck = Get-Module -ListAvailable -Name ExchangeOnlineManagement

        if (!$AzureCheck) {
            Write-Host "AzureAD module does not exist. Trying to install.."
            if($isRunAsAdministrator) {
                Install-Module -Name AzureADPreview -AllowClobber
                Import-Module -Name AzureADPreview
            } else { Write-Host "Please run the scripts using Administrator privilege." -ForegroundColor Red }
        } 
        
        if (!$EXOCheck) {
            Write-Host "ExchangeOnlineManagement module does not exist. Trying to install.."
            if($isRunAsAdministrator) {
                Install-Module -Name ExchangeOnlineManagement
                Import-Module -Name ExchangeOnlineManagement
            } else { Write-Host "Please run the scripts using Administrator privilege." -ForegroundColor Red }
        }
        $basicAuth = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\).AllowBasic
        Write-Host "Checking BasicAuth:" ($basicAuth -eq 1) `n
        if($basicAuth -eq 0 -and $AuditLogOn) {
            if($isRunAsAdministrator) {
                Set-ExecutionPolicy RemoteSigned
                #winrm set winrm/config/client/auth @{Basic="true"}
                Set-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic" -Value 1
                winrm quickconfig -force
            } else { Write-Host "Extended AuditLog is ON but BasicAuth for WimRM is not enabled. Please run as Administrator."`n -ForegroundColor Red; Break }
        } 
    ################################################################

    
    try 
    { $var = Get-AzureADTenantDetail } 
    catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] 
    { 
        Write-Host "You're not connected. Trying to connect to AzureAD..";
        try {
            if (Test-Path $credsFile -PathType Leaf) { 
                $creds = Import-Clixml -Path $credsFile
            } else {
                $creds = Get-Credential
                $creds | Export-Clixml -Path $credsFile
            }
            Write-Host "Connecting to AzureAD"
            Connect-AzureAD -Credential $creds
            $hasEXO = Get-PSSession
            if(!$hasEXO) { 
                Write-Host "Connecting to EXO"
                #Connect-ExchangeOnline -Credential $creds 
            }
        } catch { 
            try { Connect-AzureAD }
            catch { Break }
        }
    }
}

# Initialize an user objects, more info will be pushed to it later
function initUser {
param(
    [Parameter(Mandatory)]
    [string]$username
    )

    if($username.IndexOf("@") -eq -1) {
        $username += $domain
    }
    $username = $username.Trim()

    Write-Host $username -ForegroundColor Yellow
    # Init user
    $user = New-Object -TypeName psobject
    $user | Add-Member -MemberType NoteProperty -Name Email -Value "$username"
    $user | Add-Member -MemberType NoteProperty -Name Compromised -Value $false
    $user | Add-Member -MemberType NoteProperty -Name CompReason -Value $null

    return $user
}    


function getIPLocation {
param(
    [Parameter(Mandatory)]
    [hashtable]$table,
    [Parameter(Mandatory)]
    [string]$ip
    )

    # Country check for IPv6
    if ($table[$ip] -eq $null) { 
        $api = curl "ipinfo.io/$($ip)?token=$IPTOKEN"
        #$json = ($api -replace '\n', '') | ConvertFrom-Json 
        $location = ConvertFrom-Json -InputObject $api
        $table[$ip] = @($location)
        Write-Debug "IP API called"
    } else {
        $location = $table[$ip]
    }

    return $location
}

function getProxyType {
param(
    [Parameter(Mandatory)]
    [hashtable]$table,
    [Parameter(Mandatory)]
    [string]$ip
    )

    if(!$VPNTOKEN) { $VPNTOKEN = "demo" }
    # Country check for IPv6
    if ($table[$ip] -eq $null) { 
        $api = curl "http://api.ip2proxy.com/?ip=$($ip)&key=$($VPNTOKEN)&package=PX2"
        $proxy = ConvertFrom-Json -InputObject $api
        $table[$ip] = @($proxy)
        Write-Debug "IP API called"
    } else {
        $proxy = $table[$ip]
    }

    return $proxy
}

# Set time-limit for user's sign-in logs since the last password reset date OR the last 90 days
# Force mode (-f) force to get log in the last 90 days
function timeFilter {
param(
    [Parameter()]
    [PSObject]$lastset = $null,
    [Parameter()]
    [switch]$f
    )

    if (($lastset -eq $null) -or ($lastset -eq "Unable to obtain, limit set to the last 90 days") -or ($f))
    {
        $lastset = (GET-DATE).AddDays(-90).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ")
    } else { 
        $lastsetts = New-TimeSpan -End (GET-DATE) -Start $lastset
        if($lastsetts.Days -gt 90) { $lastset = (GET-DATE).AddDays(-90).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ") }
        else { $lastset = $lastset.AddHours(3).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ") }
    }
    return $lastset
}


# Get user information (password last set, local group) from LocalAD or AzureAD
function getLocalAD {
param(
    [Parameter(Mandatory)]
    [PSObject]$user
    )
    
    $email = $user.Email

    if($LocalADon) {
        try {
            # Get User information from the local AD
            $localAD = Get-ADUser -Filter {enabled -eq $true -and UserPrincipalName -eq $email} -Properties DistinguishedName, MemberOf, LastBadPasswordAttempt, PasswordLastSet, LastLogonTimestamp, LastLogonDate
            # Get user's group info
            $userGroup = ($LocalAD.DistinguishedName -split ",OU=")[1]
            $user | Add-Member -MemberType NoteProperty -Name VPN -Value $false
            $isVPN = $LocalAD.MemberOf
            if("$isVPN".IndexOf("VPN") -ne -1){
                $user.VPN = $true
            }
            $lastset = ($localAD.PasswordLastSet)
        } catch { 
            Write-Host "Unable to fetch from Local AD. Make sure the user exists and/or you have VPN connected" -ForegroundColor Yellow
            Write-Host "Using AzuredAD as an alternative"    
        }
    }
    
    if(!$localAD){
        $localAD = Get-AzureADUser -Filter "userPrincipalName eq '$email'" | Select *
        #$localAD = Get-MsolUser -userPrincipalName "$email" | Select *
        $userGroup = (($localAD | Select -ExpandProperty ExtensionProperty).onPremisesDistinguishedName -split ",OU=")[1]
        $lastset = $localAD.RefreshTokensValidFromDateTime
    }

    #Write-Host ($lastset | Out-String) "Zzz"

    $lastset = if ($lastset) { $lastset } else { "Unable to obtain, limit set to the last 90 days" }
    $user | Add-Member -MemberType NoteProperty -Name LastSet -Value $lastset
    $user | Add-Member -MemberType NoteProperty -Name LocalAD -Value $localAD
    $user | Add-Member -MemberType NoteProperty -Name LocalGroup -Value $userGroup
        
    return $user
}


# Dumping AzureAD success sign-in logs using preset filter
function getAzureLogs {
param(
    [Parameter(Mandatory)]
    [PSObject]$user,
    [Parameter()]
    [int]$samples = $null,
    [Parameter()]
    [switch]$f
    )

    $email = $user.email

  
    # Set time for the filter
    $lastset = timeFilter $user.LastSet -f:$f
    
    # Get AzureAD logs
    $filter = "userPrincipalName eq '$email' and status/errorCode eq 0 and createdDateTime ge $lastset"
    $logs = Get-AzureADAuditSignInLogs -Filter $filter -Top $samples
    $user | Add-Member -MemberType NoteProperty -Name Logs -Value $logs
    $user.Logs | Where { $_ | Select -Exp Location | Where CountryOrRegion -eq $null } | % { 
        $ipLoc = getIPLocation $IPTable $_.IpAddress
        $_.Location.City = $ipLoc.city
        $_.Location.State = $ipLoc.region
        $_.Location.CountryOrRegion = $ipLoc.country
    }

    return $user
}


# Analyze and extract risk logs
function getRiskLogs {
param(
    [Parameter(Mandatory)]
    [PSObject]$user,
    [Parameter()]
    [int]$samples = $null,
    [Parameter()]
    [switch]$f
    )
    
    # Most obvious sign: multiple countries = redflag
    $hopCount = (($user.Logs.Location | Group-Object CountryOrRegion | Sort Count -Descending) | Measure-Object).Count
    if($hopCount -gt $HopsLimit) { 
        $user.Compromised = $true
        $user.CompReason = " # Countries Hopper"
        }

    $emptyDevices = $user.Logs | Where { $_ | Select -Exp DeviceDetail | Where { ($_.DisplayName -eq $null) -and 
                                                                 ($_.OperatingSystem -eq $null) -and 
                                                                 ($_.Browser -eq $null) } 
                                        }
    #Write-Host "Yolo"
    #Write-Host ($emptyDevices.Count/$user.Logs.Count) "Zzzzz" -ForegroundColor Red

    # If a "bad protocol"/emptydevice is used most of the time and had enough samples, it's likely legit for legacy client
    if(($user.Logs.Count -gt $forceRisk) -and 
        ($emptyDevices.Count/$user.Logs.Count -ge 0.8) -and
        ($hopCount -lt $HopsLimit) ) {
            $emptyDevices | % { 
                $_.DeviceDetail.Browser = $_.ClientAppUsed
                $_.DeviceDetail.OperatingSystem = $_.AppDisplayName
            }
    }

    # Get baseline for everything
    $baseCountry = $user.Logs.Location | Group-Object CountryOrRegion | Sort Count -Descending | Select -First 1 Name, Count
    $baseState = $user.Logs.Location | Group-Object State | Sort Count -Descending  | Select -First 1 Name
    $baseIP =  $user.Logs | Where { ($BadProtocols -notcontains $_.ClientAppUsed) -and 
                                     ($_ | Select -Exp Location | Where State -eq $baseState.Name) -and 
                                     ($_| Select -Exp DeviceDetail | Where {($_.DisplayName -ne $null) -or 
                                                                            ($_.OperatingSystem -ne $null) -or 
                                                                            ($_.Browser -ne $null)} )
                                  } | Group-Object IpAddress | Sort Count -Descending | Select -First $safeIP Name, Count
   
    # Get all connected devices from baseIP(s)
    $baseDevices = @()
    #$baseIP | % { $baseDevices += ($user.Logs | Where IpAddress -eq $_.Name | Group-Object DeviceDetail | Sort Count -Descending | Select Name) }
    $baseIP | % { 
        $tmp = $_.Name
        $baseDevices += ($user.Logs | Where { 
                                        #$inlog = $_
                                        ($BadProtocols -notcontains $_.ClientAppUsed) -and 
                                        ($_.IpAddress -eq $tmp) -and 
                                        ($_ | Select -Exp DeviceDetail | Where { 
                                                                                ($_.DisplayName -ne $null) -or 
                                                                                ($_.OperatingSystem -ne $null) -or 
                                                                                ($_.Browser -ne $null) 
                                                                                } )
                                        } | Group-Object DeviceDetail | Sort Count -Descending | Select Name)
    }
    $baseDevices = @($baseDevices | Group-Object Name | Sort Count -Descending | Select Name)
    #Write-Host $baseDevices

    # Get top #n devices from logs regardless IPs, n = reference number of devices from the baseIPs
    # Exclude bad/legacy protocols as they usually have no DeviceDetail
    $ref = ($baseDevices | Measure-Object).Count
    #Write-Host ($user.Logs | Where { ($BadProtocols -notcontains $_.ClientAppUsed) } | Group-Object DeviceDetail | Sort Count -Descending | Select -First $ref Name) -ForegroundColor Red
    if($extend) {
        $baseDevices += ($user.Logs | Where { ($BadProtocols -notcontains $_.ClientAppUsed) -and 
                                              ($_ | Select -Exp Location | Where State -eq $baseState.Name)  -and 
                                              ($_ | Select -Exp DeviceDetail | Where { 
                                                                                ($_.DisplayName -ne $null) -or 
                                                                                ($_.OperatingSystem -ne $null) -or 
                                                                                ($_.Browser -ne $null) 
                                                                                } )
                                         } | Group-Object DeviceDetail | Sort Count -Descending | Select -First $ref Name)
        #Write-Host ($user.Logs | Where { ($BadProtocols -notcontains $_.ClientAppUsed) -and ($baseDevices.Name -notcontains $_.DeviceDetail) } | Group-Object DeviceDetail | Sort Count -Descending | Select -First $ref Name) -ForegroundColor Red
    } 

    # Get trusted/registered devices
    $baseDevices += ($user.Logs | Where { ($baseDevices.Name -notcontains $_.DeviceDetail) -and 
                                          ($_ | Select -Exp DeviceDetail | Where TrustType -ne $null) } | 
                                            Group-Object DeviceDetail | Sort Count -Descending | Select Name)
    
    #Write-Debug (($user.Logs | Group-Object DeviceDetail | Sort Count -Descending | Select Name, Count).Name | Out-String)
    Write-Debug "########"
    #Write-Debug $baseDevices

    $baseDevices = ($baseDevices | Group-Object Name | Sort Count -Descending | Select Name)
    Write-Debug ("Total baseDevices: " + $baseDevices.Count)
    Write-Debug ($baseDevices.Name | Out-String)

    # Fullfill empty device
    $emptyDevices | % { 
                    $_.DeviceDetail.Browser = $_.ClientAppUsed
                    $_.DeviceDetail.OperatingSystem = $_.AppDisplayName
                }
    #########################################################################################################
    #Write-Host ($user.Logs | Where { $_ | Select -Exp DeviceDetail | Where Browser -eq "IE 11.0" } )
    #########################################################################################################

    # Identify risk logs
    $riskLogs = $user.Logs | Where { 
        #(($baseDevices.Name -notcontains $_.DeviceDetail) -and ($_.MfaDetail -eq $null)) -or (($baseState.Name -ne ($_.Location.State) -and ($baseDevices.Name -notcontains $_.DeviceDetail) -and ($_.MfaDetail -eq $null)) )
        #($baseDevices.Name -notcontains $_.DeviceDetail) -and
        (($baseDevices.Name -notcontains $_.DeviceDetail) -and ($baseIP.Name -notcontains $_.IpAddress) ) -and
        (($_.MfaDetail -eq $null) -or $inMFA) -and 
        ($_.IpAddress -notmatch $whiteIP) -and 
        ($_.Location.State -notmatch $baseState)
    }

    #Write-Debug ($riskLogs | Out-String)
    Write-Debug ("Total logs: " + $user.Logs.Count)
    Write-Debug ("Risk logs: " + ($riskLogs | Measure-Object).Count | Out-String)
    

    $user | Add-Member -MemberType NoteProperty -Name BaseIP -Value $baseIP
    $user | Add-Member -MemberType NoteProperty -Name BaseDevices -Value $baseDevices
    $user | Add-Member -MemberType NoteProperty -Name BaseCountry -Value ($baseCountry)
    $user | Add-Member -MemberType NoteProperty -Name BaseState -Value $baseState
    $user | Add-Member -MemberType NoteProperty -Name RiskLogs -Value $riskLogs

    return $user
}

# For each risk logs, run an addtional analyzing
function analyzeRisks {
param(
    [Parameter(Mandatory)]
    [PSObject]$user,
    [Parameter()]
    [int]$samples = $null,
    [Parameter()]
    [switch]$f
    )

    $email = $user.email

    #Get user's password set date
    $lastset = timeFilter $user.LastSet -f:$f

    # Get AzureAD failed signin logs
    for($i = 0; $i -lt $badErrorCode.Count; $i++) { 
        if($i -eq 0) { $codeFilter += "status/errorCode eq $($badErrorCode[$i])" }
        else { $codeFilter += " or status/errorCode eq $($badErrorCode[$i])" }
    }
    # 2020-05-24T01:15:36.2936106Z
    $latestRiskTime = $user.RiskLogs | Sort CreatedDateTime -Descending | Select -First 1 CreatedDateTime
    if($latestRiskTime) { 
        $timelimit = "(createdDateTime le $($latestRiskTime.CreatedDateTime)) and (createdDateTime ge $lastset)" 
    } else { $timelimit = "(createdDateTime ge $lastset)" }

    #$filter = "(userPrincipalName eq '$email') and ($codeFilter) and (createdDateTime ge 2020-05-24T01:15:36.2936106Z)"
    $filter = "(userPrincipalName eq '$email') and ($codeFilter) and $timelimit"
    if($f) { $samples = $samples * 2}
    $failedLogs = Get-AzureADAuditSignInLogs -All:$true -Filter $filter -Top $samples
    Write-Debug $filter

    #Write-Host ($failedlogs | Out-String)
    Write-Debug ($failedlogs | Measure-Object).Count

   
    # Group (success) RiskLogs into group by IP, then select the first and oldest log of each IP
    $RiskByIP = $user.RiskLogs | Group IpAddress
    $oldestRiskbyIP = @()
    $RiskByIP | % { $oldestRiskbyIP += ($_.Group | Sort CreatedDateTime -Descending | Select -First 1)} 


    #Write-Host $oldestRiskbyIP.Count
    #$oldestRiskbyIP | % { Write-Host $_.IpAddress $_.CreatedDateTime }

    # Password-spray/bruteforce/proxy detection
    $proxyCount = 0;
    for($i=0; $i -le $oldestRiskbyIP.Count-1; $i++) {
        $current = $oldestRiskbyIP[$i].CreatedDateTime
        $next = $oldestRiskbyIP[$i+1].CreatedDateTime
        if($i -eq $oldestRiskbyIP.Count-1) {
            $next = $lastset
        }

        $prevFailed = ($failedLogs | Where {
            ($_.CreatedDateTime -le $current -and $_.CreatedDateTime -gt $next) -and 
            # + OR statement = more aggressive
            (($_.Location.State -ne $user.BaseState.Name) )#-or ($user.BaseIP -notcontains $_.IpAddress));
            } | Group IpAddress)

        Write-Debug ($current + " -> " + $next)    
        Write-Debug ("Failed attempts " + ($prevFailed | Out-String))
        Write-DeBug (($prevFailed | Measure-Object).Count)
        
        # Multiple failed attempts follow by a successful sigin
        if((($prevFailed | Measure-Object).Count -gt $HopsLimit) -or
             # If a user is not in active groups, higher risk
             ((($prevFailed | Measure-Object).Count -ge 1) -and !$activeGroups.Contains($user.LocalGroup) ) ) {
            $user.Compromised = $true
            $user.CompReason = " # Password-spray/Brute-force"
            Break
        }

        # If user has insufficient logs, treat them all as risk and run additional IP check
        # Because of the budget constraint, this only run on users with fewer logs. 
        if($user.RiskLogs.Count -le $forceRisk) {
            $IPType = getProxyType $ProxyTable $oldestRiskbyIP[$i].IpAddress
            $isProxy = ($IPType.isProxy -eq "YES" -and $IPType.proxyType -ne "VPN")
            if($isProxy) { $proxyCount++ }
            if(($proxyCount -gt $HopsLimit) -or
                 # If a user is not in active groups, higher risk
                 (($proxyCount -ge 1) -and !$activeGroups.Contains($user.LocalGroup) ) ) {
                $user.Compromised = $true
                $user.CompReason = " # Proxied Connections"
                Break
            }
        }

    }

    return $user
}


# Out put brief report to the screen
function Summary {
param(
    [Parameter(Mandatory)]
    [PSObject]$user
    )

    $user | % {
        $nTotal = ($_.Logs | Measure).Count
        $nRisks = ($_.RiskLogs | Measure).Count
        Write-Host $_.Email -ForegroundColor Yellow
        Write-Host "User Group: "`t`t`t`t $_.LocalGroup
        Write-Host "User Last Password Reset: "`t`t $_.LastSet
        Write-Host "Total logs sample: "`t`t`t $nTotal
        Write-Host "Number of risk logs: "`t`t`t $nRisks
        
        if($_.Compromised -or $nRisks -ne 0) {
            $riskPercentage = ($nRisks/$nTotal)*100
            Write-host "Risk: "`t`t`t`t`t $riskPercentage "%"
            if($_.Compromised) { Write-Host "Status: "`t`t`t`t -NoNewline; Write-Host "COMPROMISED!"`n`n -ForegroundColor Red} 
            else { Write-Host "Status: "`t`t`t`t -NoNewline; Write-Host "MONITOR"`n`n -ForegroundColor Yellow}

        } else {
            Write-Host "Status: "`t`t`t`t -NoNewline;
            Write-Host "GOOD"`n`n -ForegroundColor Green
        }
    }

}

# Nyan plays with each input
function NyanLogs {
param(
    [Parameter(Mandatory)]
    [string]$username,
    [Parameter()]
    [int]$samples = $null,
    [Parameter()]
    [switch]$f,
    [Parameter()]
    [string]$msg = "Nyan is running.."
    )

    $user = initUser $username
    Write-Progress -Activity $username -CurrentOperation ("Init user.. " + (Measure-Command {$user = getLocalAD $user }) )
    Write-Progress -Activity $username -CurrentOperation ("Getting AzureAD logs.. " + (Measure-Command {$user = getAzureLogs $user -samples $samples -f:$f }) )
    Write-Progress -Activity $username -CurrentOperation ("Identifying risk logs.. " + (Measure-Command {$user = getRiskLogs $user -samples $samples -f:$f }) )
    Write-Progress -Activity $username -CurrentOperation ("Analyzing risk logs.." + (Measure-Command {if(!$user.Compromised -and ($user.RiskLogs | Measure-Object).Count -gt 0) { $user = analyzeRisks $user -samples $samples -f:$f } }) )
    #Write-Progress -Activity $msg -CurrentOperation ("Analyzing risk logs.." + (Measure-Command {if(($user.RiskLogs | Measure-Object).Count -gt 0) { $user = analyzeRisks $user -samples $samples -f:$f } }) )
    Write-Host "## DONE ##"`n`n -ForegroundColor Yellow
    if($f) { $user.LastSet = ($user.LastSet).ToString() + " (Forcemode was ON, limit set to the last 90 days)" }
    
    #Summary $user

    return $user

}


function ConvertTo-HTMLTable ($obj) {
# Credit to: https://stackoverflow.com/users/9898643/theo
# Accepts a System.Data.DataTable object or an array of PSObjects and converts to styled HTML table
# add type needed to replace HTML special characters into entities
    Add-Type -AssemblyName System.Web

    $sb = New-Object -TypeName System.Text.StringBuilder
    [void]$sb.AppendLine('<table>')
    if ($null -ne $obj) {
        if (([object]$obj).GetType().FullName -eq 'System.Data.DataTable'){
            # it is a DataTable; convert to array of PSObjects
            $obj = $obj | Select-Object * -ExcludeProperty ItemArray, Table, RowError, RowState, HasErrors
        }
        $headers = $obj[0].PSObject.Properties | Select -ExpandProperty Name
        [void]$sb.AppendLine('<thead><tr>')
        foreach ($column in $headers) {
            [void]$sb.AppendLine(('<th>{0}</th>' -f [System.Web.HttpUtility]::HtmlEncode($column)))
        }
        [void]$sb.AppendLine('</tr></thead><tbody>')
        $row = 0
        $obj | ForEach-Object {
            # add inline style for zebra color rows
            if ($row++ -band 1) {
                $tr = '<tr style="background-color: {0};">' -f $oddRowBackColor
            } 
            else {
                $tr = '<tr>'
            }
            [void]$sb.AppendLine($tr)
            foreach ($column in $headers) {
                [string]$val = $($_.$column)
                if ([string]::IsNullOrWhiteSpace($val)) { 
                    $td = '<td>&nbsp;</td>' 
                } 
                else { 
                    $td = '<td>{0}</td>' -f [System.Web.HttpUtility]::HtmlEncode($val)
                }
                [void]$sb.Append($td)
            }
            [void]$sb.AppendLine('</tr>')
        }

        [void]$sb.AppendLine('</tbody>')
    }
    [void]$sb.AppendLine('</table>')

    return $sb.ToString()
}


function exportReport {
param(
    [Parameter(Mandatory)]
    [PSObject]$user
    )

    $IPTable | Export-Clixml -Path $IPTableFile
    $ProxyTable | Export-Clixml -Path $ProxyTableFile
    $user | Where { ($_.RiskLogs | Measure-Object).Count -gt 0 -and !$_.Compromised} | 
            Select Email, LocalGroup, LastSet, @{Name='Added Date'; Expression={(Get-Date).tostring("MM-dd-yyyy HH:mm")} } |
            Export-Csv -Append -Path $MonitorFile -NoTypeInformation
    $user | Where { $_.Compromised } | 
            Select Email, LocalGroup, LastSet, @{Name='Added Date'; Expression={(Get-Date).tostring("MM-dd-yyyy HH:mm")} } |
            Export-Csv -Append -Path $CompFile -NoTypeInformation

    $html = "
        <head>
        <title>Risk Logs Report</title>
        <meta name='viewport' content='width=device-width, initial-scale=1'>
        <link rel='stylesheet' href='https://maxcdn.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css'>
        <script src='https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js'></script>
        <script src='https://maxcdn.bootstrapcdn.com/bootstrap/4.5.0/js/bootstrap.min.js'></script>
        </head>
        <style>
        #TABLE { margin-bottom: 5px; border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse;}
        TH {border-width: 1px; padding: 3px; border-style: solid; border-color: black; background-color: #3179de;}
        TD {border-width: 1px; padding: 3px; border-style: solid; border-color: black;}
        .table-condensed {
              font-size: 12px;
        }
        .collapse.show {
          visibility: visible;
        }
        a, a:hover,a:visited, a:focus {
            text-decoration:none;
        }
        table.dataTable thead .sorting:after,
        table.dataTable thead .sorting:before,
        table.dataTable thead .sorting_asc:after,
        table.dataTable thead .sorting_asc:before,
        table.dataTable thead .sorting_asc_disabled:after,
        table.dataTable thead .sorting_asc_disabled:before,
        table.dataTable thead .sorting_desc:after,
        table.dataTable thead .sorting_desc:before,
        table.dataTable thead .sorting_desc_disabled:after,
        table.dataTable thead .sorting_desc_disabled:before {
        bottom: .5em;
        }
        </style>"
        

    ($users | Sort Compromised, { ($_.RiskLogs | Measure-Object).Count} -Descending ) | % {
        #$html += $_ | Select Email, LocalGroup, VPN, BaseIP, BaseDevices, BaseState, BaseCountry | ConvertTo-Html -Head $Header
        $html += "<div class='mb-4'>"    
        if($_.Compromised) { $riskhead = "<div class='button btn-danger text-white py-1 px-1 font-weight-bold'> $($_.Email) # COMPROMISED $($_.CompReason)</div>" }
        elseif ($_.RiskLogs -ne $null) { $riskhead = "<div class='button btn-warning text-danger py-1 px-1 font-weight-bold'>$($_.Email)</div>"}
        else {  $done = $null }
        if(($_.RiskLogs | Measure-Object).Count -gt 0 -or $_.Compromised) {
            $html += "<link rel='stylesheet' href='https://cdn.datatables.net/1.10.21/css/jquery.dataTables.min.css'>
                      <script src='https://cdn.datatables.net/1.10.21/js/jquery.dataTables.min.js'></script>"
            $html += $riskhead
            $html += $_ | Select @{Name='Email';Expression={$_.Email};}, @{Name='Group';Expression={$_.LocalGroup};},@{Name='Last Set';Expression={($_.Lastset)};}, @{Name='VPN User';Expression={ if($_.VPN) { $vcolor = "#9c0000"}; "<div style='color: $($vcolor); font-weight: bold;'>$($_.VPN)</div>" };}, @{Name='Logs';Expression={$_.Logs.Count};}, @{Name='RiskLogs';Expression={($_.RiskLogs | Measure-Object).Count};}, @{Name='BaseIP';Expression={ $_.BaseIP | % { $str+="$_ <br>" } ; $str };}, @{Name='BaseDevices';Expression={$_.BaseDevices | % { $str+="$($_.Name) <br>" } ; $str };}, @{Name='BaseState';Expression={$_.BaseState.Name};}, @{Name='BaseCountry';Expression={$_.BaseCountry};} | ConvertTo-Html -Fragment -As List
            $html2 += "<button class='btn btn-primary btn-sm btn-block mb-1 font-weight-bold' type='button' data-toggle='collapse' data-target='#$(($_.Email).Split('@')[0] )' aria-expanded='false' aria-controls='$(($_.Email).Split('@')[0] )'>View $($_.Email)'s Risky Logs</button><div id='$(($_.Email).Split('@')[0] )' class='collapse'>"
            #$html2 += $_.RiskLogs | ConvertTo-Html -Property CreatedDateTime, UserDisplayName, UserPrincipalName, AppDisplayName, IpAddress, ClientAppUsed, DeviceDetail, Location, IsInteractive, ResourceDisplayName, Status, TokenIssuerName, TokenIssuerType, ProcessingTimeInMilliseconds, RiskDetail, RiskLevelAggregated, RiskLevelDuringSignIn, RiskState, MfaDetail -Fragment
            #$html2 += ConvertTo-HTMLTable ($_.RiskLogs | Select CreatedDateTime, UserDisplayName, UserPrincipalName, AppDisplayName, IpAddress, ClientAppUsed, DeviceDetail, Location, IsInteractive, ResourceDisplayName, Status, TokenIssuerName, TokenIssuerType, ProcessingTimeInMilliseconds, RiskDetail, RiskLevelAggregated, RiskLevelDuringSignIn, RiskState, MfaDetail)
            $html2 += ConvertTo-HTMLTable ($_.RiskLogs | Select CreatedDateTime, UserDisplayName, UserPrincipalName, AppDisplayName, IpAddress, ClientAppUsed, DeviceDetail, Location, IsInteractive, ResourceDisplayName, RiskDetail, RiskLevelAggregated, RiskLevelDuringSignIn, RiskState)
            $html2 += "</div>"
            $tablelist += "
                   `$('#$(($_.Email).Split('@')[0] )_table').DataTable({
                    'order': [[0,'desc']]});
                   `$('.dataTables_length').addClass('bs-select');"
            $html += $html2 -replace "<table", "<table id='$(($_.Email).Split('@')[0] )_table'"
            $html2 = ""
        } else {
            $html += "<a class='btn-secondary' data-toggle='collapse' href='#$(($_.Email).Split('@')[0] )' role='button' aria-expanded='false' aria-controls='$(($_.Email).Split('@')[0] )'>
            <div class='button btn-secondary text-success py-1 px-1 font-weight-bold'>$($_.Email) $($done)</div></a>
            <div id='$(($_.Email).Split('@')[0] )' class='collapse'>"
            $html += $_ | Select @{Name='Email';Expression={$_.Email};}, @{Name='Group';Expression={$_.LocalGroup};},@{Name='Last Set';Expression={($_.Lastset)};}, @{Name='VPN User';Expression={ if($_.VPN) { $vcolor = "#9c0000"}; "<div style='color: $($vcolor); font-weight: bold;'>$($_.VPN)</div>" };}, @{Name='Logs';Expression={$_.Logs.Count};}, @{Name='RiskLogs';Expression={($_.RiskLogs | Measure-Object).Count};}, @{Name='BaseIP';Expression={ $_.BaseIP | % { $str+="$_ <br>" } ; $str };}, @{Name='BaseDevices';Expression={$_.BaseDevices | % { $str+="$($_.Name) <br>" } ; $str };}, @{Name='BaseState';Expression={$_.BaseState.Name};}, @{Name='BaseCountry';Expression={$_.BaseCountry};} | ConvertTo-Html -Fragment -As List
            $html += "</div>"
        }
        $html += "</div>"
    }
    $html += "<script>
        `$(document).ready(function () {
        $($tablelist)
        });
        </script>"
    $html = $html -replace "class SignIn",""
    $html = $html -replace "<table","<div class=' table-responsive'><table class='table table-sm table-striped table-condensed table-hover mb-0'"
    $html = $html -replace "</table>","</table></div>"
    $html +="        <center>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;'>▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;'>▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;'>▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▄▀▒▒▒▒▒▒▒▒▒▒▒▒▄▒▒▒▒▒▒▒▀▄▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;color:red;'>▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span><span style='font-size:12px;line-height:107%;'>█▒▒▄▒▒▒▒▄▒▒▒▒▒▒▒▒▒▒▒▒▒▒█▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;color:#FFC000;'>▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span><span style='font-size:12px;line-height:107%;'>█▒▒▒▒▒▒▒▒▒▒▒▒▄█▄▄▒▒▄▒▒▒█▒▄▄▄▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;color:yellow;'>▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span><span style='font-size:12px;line-height:107%;'>▄▄▄▄▄<span style='color:yellow;'>▒▒</span>█▒▒▒▒▒▒▀▒▒▒▒▀█▒▒▀▄▒▒▒▒▒█▀▀▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;color:#92D050;'>▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span><span style='font-size:12px;line-height:107%;'>██▄▀██▄█▒▒▒▄▒▒▒▒▒▒▒██▒▒▒▒▀▀▀▀▀▒▒▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;color:#00B0F0;'>▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span><span style='font-size:12px;line-height:107%;'>▀██▄▀██▒▒▒▒▒▒▒▒▀▒██▀▒▒▒▒▒▒▒▒▒▒▒▒▒▀██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;color:#2a00fa;'>▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span><span style='font-size:12px;line-height:107%;'>▀████▒▀▒▒▒▒▄▒▒▒██▒▒▒▄█▒▒▒▒▄▒▄█▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;color:#9a00fa;'>▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span><span style='font-size:12px;line-height:107%;'>▀█▒▒▒▒▄▒▒▒▒▒██▒▒▒▒▄▒▒▒▄▒▒▄▒▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;'>▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▄█▄▒▒▒▒▒▒▒▒▒▒▒▀▄▒▒▀▀▀▀▀▀▀▀▒▒▄▀▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;'>▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒█▀▀█████████▀▀▀▀████████████▀▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;'>▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒████▀▒▒███▀▒▒▒▒▒▒▀███▒▒▀██▀▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;'>▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;'>&nbsp;</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'>&nbsp;</p>
        </center>"

    [System.Web.HttpUtility]::HtmlDecode($html) | Out-File $ReportFile

    #$users.RiskLogs | ConvertTo-Html -Property CreatedDateTime, UserDisplayName, UserPrincipalName, AppDisplayName, IpAddress, ClientAppUsed, DeviceDetail, Location, IsInteractive, ResourceDisplayName, Status, TokenIssuerName, TokenIssuerType, ProcessingTimeInMilliseconds, RiskDetail, RiskLevelAggregated, RiskLevelDuringSignIn, RiskState, MfaDetail -Head $Header

}


function sendReport {

    if($sendMail) {
        if($silentMail) { Send-MailMessage @mailconf; Write-Debug "Mail sent" }
        else {
            $sending = Read-Host "Send report to preset emails? (y/N): "
            if(@("y","Y").Contains($sending)) {
                try {
                    Send-MailMessage @mailconf
                } catch { Write-Host "Mail sending failed" -ForegroundColor Yellow }
                Write-Debug "Mail sent"
            }
        }
    }

}

# Extract (unique) emails from abitrary file format using RegEx
function extractEmails {
param(
    [Parameter(Mandatory)]
    [string]$content
    )

    $emails = (Select-String -Path $content  -Pattern $emailRegEx -AllMatches | % { $_.Matches } | % { $_.Value } | Select -Unique).Trim()
    return $emails
}



function Main {
    Clear-Host
    Write-Host "###########################`n# Nyanalyzer $thisversion         #`n# Ferris State University #`n###########################`n`n" -ForegroundColor Yellow
    #printNyan

    #try 
    #{ $var = Get-AzureADTenantDetail } 
    #catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] 
    #{ Write-Host "You're not connected."; Connect-AzureAD }

    goAzureAD

    if($isDebug) { Write-Host "DEBUG MODE"`n -ForegroundColor Red }
    if($username) {
        #try {
        $users = @()
            if (Test-Path $username -PathType Leaf) {
                $i = 0;
                $totalItems = extractEmails $username
                foreach($item in $totalItems) {
                    $i++
                    $Activity = "Nyan is running.."
                    Write-Progress -Activity $item -Status "Progress: $i / $($totalItems.Count)" -PercentComplete (($i / $totalItems.Count)  * 100)
                    $users += (NyanLogs -username $item -samples $samples -f:$f)
                    #Write-Debug ($tmp | Out-String)
                }

            } else { $username.Split(",") | % { $users += (NyanLogs -username $_ -samples $samples -f:$f) } }
            
            if(!$isDebug) { Clear-Host; printNyan }

            Summary $users
            exportReport $users
            sendReport
            if($hasEXO) {
                Disconnect-ExchangeOnline -Confirm:$false
            }
        #} catch { 
        #    $ErrorMessage = $_.Exception.Message
        #    $FailedItem = $_.Exception.ItemName
        #    Write-Host $ErrorMessage
        #    Disconnect-ExchangeOnline -Confirm:$false
        #}
    } else {
        Write-Host "Usage: ./nyanalyzer.ps1 <input file OR a single email> [number of log samples] [-f] [-debug]
        # The script accepts up to 4 parameters
        # The first one is required: could be a list of emails in file, or a single email or an inline list of users `"user1, user2`"
        # The second one is optional: define the number of log sample you want to analyze
        # -f: force the script to get logs from the last 90 days
        # -debug: debug mode
        " -ForegroundColor Yellow
    }

    # DEBUG here
    if($isDebug) {
        Write-Debug ($users.baseCountry | Out-String)
        Write-Debug ($users.baseIP | Out-String)
        #Write-Debug ($user.Logs | Out-String)      
        Write-Debug ($IPTable | Out-String)

    }
    
}

#try {
    $runtTime = (Measure-Command { Main })
    $runtTime | select @{n="Run time";e={$_.Minutes,"Minutes",$_.Seconds,"seconds",$_.Milliseconds,"ms" -join " "}}
#} catch { 
#    $ErrorMessage = $_.Exception.Message
#    $FailedItem = $_.Exception.ItemName
#    Write-Host $ErrorMessage
#}