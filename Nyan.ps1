# Nyanalyzer - An AzureAD users' activities analyzer
# Version: 1.0 @ 06/17/2020
# Tri Bui @ Ferris State University
#
# Usage: ./nyanalyzer.ps1 <input file OR a single email> [number of log samples] [-f] [-debug]
# The script accepts up to 6 parameters
# The first one is required: could be a list of emails in file, or a single email or an inline list of users "user1, user2"
# The second one is optional: define the number of log sample you want to analyze
# -f: force the script to get logs from the last 90 days
# -debug: debug mode
# -killEXO switch: kill EXO connection without asking, reserved
# -keep switch: keep EXO connection without asking, reserved

param(
    [Parameter()]
    [string]$username,
    [Parameter()]
    [int]$samples = $null,
    [Parameter()]
    [switch]$f,
    # -killEXO switch: kill EXO connection without asking, reserved
    [Parameter()]
    [switch]$killEXO,
    # -keep switch: keep EXO connection without asking, reserved
    [Parameter()]
    [switch]$keep
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
$LocalADOn = $true

# Enable (Mailbox) AuditLogs analyze and define Operations to search (* for all)
$AuditLogOn = $true
$AuditOperations = @("New-InboxRule", "Set-InboxRule")
$RiskRules = @("DeleteMessage","SubjectOrBodyContainsWords",
                "SubjectContainsWords","FromAddressContainsWords",
                "ForwardTo","ForwardAsAttachmentTo")

$badKeys = @("@","password","delete","do not open","change","compromise",
             "phishing","job","payroll","it server","webmaster","web master",
             "help desk","helpdesk","security","administrator","not me",
             "not from me","apply","interested","legit","scam","spam")


# Number of the most frequent access IP (within the same State) to deem as "safe" (baseIP)
$safeIP = 2

# Extended range of the baseDevices, base on the most used Client App
$extend = $true

# Country hop threshold - how many different countries from the logs to trigger the compromised flag
$HopsLimit = 2

# Include MFA logs in the risk logs
$inMFA = $false

# API token for IP service (ipinfo.io) # Free account has 50,000 queries/month
$IPTOKEN = ""

# Using an array of free API keys for rotation ;)
# APi token for ip2proxy.com
$VPNTOKEN1 = @("")
# API token for proxy detection (proxycheck.io) # Free account has 1000 queries/day
$VPNTOKEN = @("")
$nToken = 0

# File name settings
$reportFolder = ((Get-Location).Path) + "\NyanReports\"
$tmp = Test-Path $reportFolder
if(!($tmp))
{
      New-Item -ItemType Directory -Force -Path $reportFolder
}

$ReportFile = $reportFolder + "\Nyan-Analyzing-Results_" + (Get-Date).tostring("MM-dd-yyyy") + ".html"
$MonitorFile = $reportFolder + "\Nyan-Monitoring-Users.csv"
$CompFile = $reportFolder + "\Nyan-Compromised-Users.csv"
$credsFile = ".\NyanData\creds.xml"

# IP Proxy table
$ProxyTableFile = ".\NyanData\ProxyTable.xml"
if (Test-Path $ProxyTableFile -PathType Leaf) {
    $ProxyTable = Import-Clixml $ProxyTableFile
} else { $ProxyTable = @{} }

# IP to country table
$IPTableFile = ".\NyanData\IPLocation.xml"
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
$WhiteIP = "^161\.57\.([1-9]?\d|[12]\d\d)\.([1-9]?\d|[12]\d\d)$|^204\.38\.(2[4-9]|3[01])\.([1-9]?\d|[12]\d\d)$"
$badErrorCode = @("50053","50126")
# If base Country is from the badCountries, they're risks.
$badCountries = @("NG")

# Whitelist Localtion
$whiteCountries = @("US")
$whiteState = @("Michigan")

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
    [string]$credsFile = ".\NyanData\creds.xml"
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
            } else { Write-Host "Please run the scripts using Administrator privilege." -ForegroundColor Red; Break }
        } 
        
        if (!$EXOCheck) {
            Write-Host "ExchangeOnlineManagement module does not exist. Trying to install.."
            if($isRunAsAdministrator) {
                Install-Module -Name ExchangeOnlineManagement
                Import-Module -Name ExchangeOnlineManagement
            } else { Write-Host "Please run the scripts using Administrator privilege." -ForegroundColor Red; Break}
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

    if (Test-Path $credsFile -PathType Leaf) { 
        $creds = Import-Clixml -Path $credsFile
    } else {
        $creds = Get-Credential
        $creds | Export-Clixml -Path $credsFile
    }
    
    try 
    { $var = Get-AzureADTenantDetail } 
    catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] 
    { 
        Write-Host "You're not connected. Trying to connect to AzureAD..";
        try {
            Write-Host "Connecting to AzureAD"
            Connect-AzureAD -Credential $creds
        } catch { 
            try { Connect-AzureAD }
            catch { Break }
        }
    }
    
    $hasEXO = Get-PSSession
    if(!$hasEXO -and $AuditLogOn) { 
        Write-Host "Connecting to EXO"
        Connect-ExchangeOnline -Credential $creds 
    }
}


#########################################################################################################
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
        Write-Debug "IP API called (ipinfo.io)"
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

    $ip = $ip.Trim()
    Write-Debug $ip
    if($table[$ip] -eq $null) {
        $url = "http://proxycheck.io/v2/$($ip)?key=$($VPNTOKEN)&days=60&vpn=1&asn=1&node=1&time=1&inf=1&risk=2&port=1&seen=1&tag=msg"
        $api = curl $url
        $proxy = ConvertFrom-Json -InputObject $api
        #Write-Host $url $proxy."$($ip)"
        $table[$ip] = $proxy."$($ip)"
        $proxy = $proxy."$($ip)"
        Write-Debug "IP API #1 called (proxycheck.io)"
    } else {
        $proxy = $table[$ip]
    }

    return $proxy
}


# Analyze if IPs are VPNs/Proxies, known threats, etc from proxycheck.io
function getProxyRisk {
param(
    [Parameter(Mandatory)]
    [hashtable]$table,
    [Parameter(Mandatory)]
    [string]$ip
    )

    $ips = ""
    $RiskCount = 0
    $ip.Split(",") | % { if($table[$_] -eq $null) { $ips += "$($_)," } }
    $ips = $ips.TrimEnd(",")

    if($ips.Split(",")[0] -ne "") {
        $api = curl -Method Post "http://proxycheck.io/v2/?key=$($VPNTOKEN)&days=60&vpn=1&asn=1&node=1&time=1&inf=1&risk=2&port=1&seen=1&tag=msg" -Body "ips=$($ips)"
        $proxy = ConvertFrom-Json -InputObject $api
        $ips.Split(",") | % {
            $table[$_] = $proxy.$_
        }
        Write-Debug "Multi-IP API called (proxycheck.io)"
    }

    $ip.Split(",") | % { 
        if($table[$_] -ne $null) {
            # If proxy buy not VPN = risk
            if(($table[$_].isProxy -eq "YES" -and $table[$_].Proxytype -ne "VPN") -or 
                ($table[$_].Proxy -eq "yes" -and $table[$_].type -ne "VPN")) {
                    $RiskCount++
            # VPN + known attack history = risk
            # Change to comment to switch between riskscore and attack history base
            } elseif ($table[$_].'attack history' -or $table[$_].risk -gt 66) { $RiskCount++  }
            #} elseif ($table[$_].risk -ge 66) { $RiskCount++  }
        }   
    
    }
    Write-Debug ($table | % {($_.isProxy -eq "YES" -or $_.Proxy -eq "yes")} | Out-String)

    return $RiskCount

}


function getProxyType2 {
param(
    [Parameter(Mandatory)]
    [hashtable]$table,
    [Parameter(Mandatory)]
    [string]$ip
    )

    $credit = (curl "https://api.ip2proxy.com/?key=$($VPNTOKEN1)&check=true" | ConvertFrom-Json).response
    Write-Debug "IP2Proxy Credit: $($credit)"
    if($credit -gt 0) {

        if(!$VPNTOKEN1) { $VPNTOKEN1 = "demo" }

        if (($table[$ip] -eq $null) -or (!$table[$ip].isProxy -and $table[$ip].Proxy -eq "no")) { 
            $api = curl "http://api.ip2proxy.com/?ip=$($ip)&key=$($VPNTOKEN1)&package=PX2"
            $proxy = ConvertFrom-Json -InputObject $api
            #$table[$ip] = @($proxy)
            $table[$ip] = $proxy
            Write-Debug "IP API #2 called (ip2proxy.com)"
        } else {
            $proxy = $table[$ip]
        }
    } else { Write-Host "ip2proxy.com key limit reached, please update a new key." -ForegroundColor Red }
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
        else { $lastset = $lastset.AddHours(0).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ") }
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


# Credit to flimbot for this function
# https://github.com/Azure/azure-docs-powershell-azuread/issues/337#issuecomment-586021444
Function Get-AzureADAuditSignInLogs2 {
    Param(
        [parameter(Mandatory=$false)]
        [System.Boolean]
        $All,
        [parameter(Mandatory=$false)]
        [parameter(ParameterSetName='GetQuery')]
        [System.Int32]
        $Top,
        [parameter(Mandatory=$false)]
        [parameter(ParameterSetName='GetQuery')]
        [System.String]
        $Filter
    )
    #Find token from previous 'Connect-AzureAD' command
    #https://stackoverflow.com/questions/49569712/exposing-the-connection-token-from-connect-azuread
    $accessToken = $null
    try{
        $accessToken = [Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens['AccessToken'].AccessToken
        
    }
    catch {
        Throw 'Please run Connect-AzureAD to connect prior to running this command'
    }

    if($accessToken) {
        $querystringparams = @{}

        if($All) {
            $querystringparams['all'] = 'True'
        }

        if($Top) {
            $querystringparams['$top'] = $Top
        }

        if($Filter) {
            $querystringparams['$filter'] = $Filter
        }

        $domain = 'graph.microsoft.com'
        $url = "https://$domain/beta/auditLogs/signIns"
    
        if($querystringparams.Count -gt 0) {
            Add-Type -AssemblyName System.Web
            $url = $url + "?" + (($querystringparams.Keys | %{ [System.Web.HttpUtility]::UrlEncode($_) + "=" + [System.Web.HttpUtility]::UrlEncode($querystringparams[$_]) }) -join '&')
        }

        $headers = @{
            'Authorization' = "Bearer $accessToken";
            'Host' = $domain;
            'Accept' = 'application/json';
            'cmdlet-name' = 'Get-AzureADAuditSignInLogs'
            'Accept-Encoding' = 'gzip, deflate'
        }

        (Invoke-RestMethod -Method Get -Uri $url -Headers $headers).value
    }
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
    $logs = Get-AzureADAuditSignInLogs -Filter $filter -Top $samples -All:$true
    $user | Add-Member -MemberType NoteProperty -Name Logs -Value $logs
    $user.Logs | Where { $_ -ne $null -and $_.Location.CountryOrRegion -eq $null } | % { 
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
    
    if(($user.Logs | Measure-Object).Count -gt 0) {
        $emptyDevices = $user.Logs | Where { ($_.DeviceDetail.DisplayName -eq $null) -and 
                                             ($_.DeviceDetail.OperatingSystem -eq $null) -and 
                                             ($_.DeviceDetail.Browser -eq $null) 
                                            }

        $hopCount = (($user.Logs.Location | Group-Object CountryOrRegion | Sort Count -Descending) | Measure-Object).Count
        # If a "bad protocol"/emptydevice is used most of the time and had enough samples, it's likely legit for legacy client
        if((($user.Logs | Measure-Object).Count -gt $forceRisk) -and 
            ($emptyDevices.Count/$user.Logs.Count -ge 0.8) -and
            ($hopCount -lt $HopsLimit) -and
            !$user.Compromised) {
                $emptyDevices | % { 
                    $_.DeviceDetail.Browser = $_.ClientAppUsed
                    $_.DeviceDetail.OperatingSystem = $_.ClientAppUsed
                    #$_.DeviceDetail.OperatingSystem = $_.AppDisplayName
                }
        }


        $baseDevices = @()
        $baseUA = @()

        # Get trusted/registered devices
        $trustedDevices += ($user.Logs | Where { ($_.DeviceDetail.TrustType -ne $null) } | Select -Exp DeviceDetail)
        $trustedUA += ($user.Logs | Where { ($_.DeviceDetail.TrustType -ne $null) } | Select userAgent)

        if($trustedDevices) {

            $baseCountry = @($user.Logs | Where {($badCountries -notcontains $_.Location.CountryOrRegion) -and
                                                         ($trustedDevices -contains $_.DeviceDetail) 
                                                         } | Select -Exp Location | Group-Object CountryOrRegion | Sort Count -Descending | Select Name, Count)
       
            $baseState = @($user.Logs | Where { ($badCountries -notcontains $_.Location.CountryOrRegion) -and
                                                         ($trustedDevices -contains $_.DeviceDetail) 
                                                         } | Select -Exp Location | Group-Object State | Sort Count -Descending | Select Name, Count)

            $baseIP =  $user.Logs | Where { ($trustedDevices -contains $_.DeviceDetail)
                                          } | Group-Object IpAddress | Sort Count -Descending | Select Name, Count

            $baseIP | % { 
                $tmp = $_.Name
                $baseDevices += ($user.Logs | Where { 
                                                #$inlog = $_
                                                #($BadProtocols -notcontains $_.ClientAppUsed) -and 
                                                ($_.IpAddress -eq $tmp) -and 
                                                ( ($_.DeviceDetail.DisplayName -ne $null) -or 
                                                  ($_.DeviceDetail.OperatingSystem -ne $null) -or 
                                                  ($_.DeviceDetail.Browser -ne $null) )
                                                } | Select -Exp DeviceDetail)

                $baseUA += ($user.Logs | Where { 
                                                #$inlog = $_
                                                #($BadProtocols -notcontains $_.ClientAppUsed) -and 
                                                ($_.IpAddress -eq $tmp) -and 
                                                ( ($_.DeviceDetail.DisplayName -ne $null) -or 
                                                  ($_.DeviceDetail.OperatingSystem -ne $null) -or 
                                                  ($_.DeviceDetail.Browser -ne $null) )
                                                } | Select userAgent)
                        }


                                
            $baseDevices += $trustedDevices
            $baseDevices = @($baseDevices | Where { $_ -ne $null } | Select -Unique)

            $baseUA += $trustedUA
            $baseUA = @($baseUA | Where { $_ -ne $null } | Select -Unique)
        
            #Write-Host $trustedDevices -ForegroundColor Yellow
            #Write-Host $baseDevices

        } 

        if( !$trustedDevices -or ($whiteCountries -notcontains $baseCountry.Name) ){
            # Get baseline for everything
            $baseCountry += @($user.Logs | Where { $badCountries -notcontains $_.Location.CountryOrRegion -and 
                                                            ( ($_.DeviceDetail.DisplayName -ne $null) -or 
                                                              ($_.DeviceDetail.OperatingSystem -ne $null) -or 
                                                              ($_.DeviceDetail.Browser -ne $null) ) } | 
                                                    Group-Object { $_.Location.CountryOrRegion } | Sort Count -Descending | Select -First 1 Name, Count)
            $baseState += @($user.Logs | Where { $badCountries -notcontains $_.Location.CountryOrRegion -and 
                                                            ( ($_.DeviceDetail.DisplayName -ne $null) -or 
                                                              ($_.DeviceDetail.OperatingSystem -ne $null) -or 
                                                              ($_.DeviceDetail.Browser -ne $null) ) } | 
                                                    Group-Object { $_.Location.State } | Sort Count -Descending | Select -First 1 Name, Count)
            $baseIP =  $user.Logs | Where { # ($BadProtocols -notcontains $_.ClientAppUsed) -and 
                                             ($_.Location.State -eq $baseState.Name) -and 
                                             ( ($_.DeviceDetail.DisplayName -ne $null) -or 
                                               ($_.DeviceDetail.OperatingSystem -ne $null) -or 
                                               ($_.DeviceDetail.Browser -ne $null) ) -and
                                             ($badCountries -notcontains $_.CountryOrRegion)
                                          } | Group-Object IpAddress | Sort Count -Descending | Select -First $safeIP Name, Count
   
            # Get all connected devices from baseIP(s)
            #if(!$baseDevices) { $baseDevices = @() }

            #$baseIP | % { $baseDevices += ($user.Logs | Where IpAddress -eq $_.Name | Group-Object DeviceDetail | Sort Count -Descending | Select Name) }
            $baseIP | % { 
                $tmp = $_.Name
                $baseDevices += ($user.Logs | Where { 
                                                #$inlog = $_
                                                #($BadProtocols -notcontains $_.ClientAppUsed) -and 
                                                ($_.IpAddress -eq $tmp) -and 
                                                ( ($_.DeviceDetail.DisplayName -ne $null) -or 
                                                  ($_.DeviceDetail.OperatingSystem -ne $null) -or 
                                                  ($_.DeviceDetail.Browser -ne $null) )
                                                } | Select -exp DeviceDetail)

                $baseUA += ($user.Logs | Where { 
                                                #$inlog = $_
                                                #($BadProtocols -notcontains $_.ClientAppUsed) -and 
                                                ($_.IpAddress -eq $tmp) -and 
                                                ( ($_.DeviceDetail.DisplayName -ne $null) -or 
                                                  ($_.DeviceDetail.OperatingSystem -ne $null) -or 
                                                  ($_.DeviceDetail.Browser -ne $null) )
                                                } | Select userAgent)
                        }


            # Get top #n devices from logs regardless IPs, n = reference number of devices from the baseIPs
            # Exclude bad/legacy protocols as they usually have no DeviceDetail
            $ref = ($baseDevices | Measure-Object).Count
            #Write-Host ($user.Logs | Where { ($BadProtocols -notcontains $_.ClientAppUsed) } | Group-Object DeviceDetail | Sort Count -Descending | Select -First $ref Name) -ForegroundColor Red
            if($extend) {
                $baseDevices += ($user.Logs | Where { #($BadProtocols -notcontains $_.ClientAppUsed) -and 
                                                      ($_.Location.State -eq $baseState.Name)  -and 
                                                      ( ($_.DeviceDetail.DisplayName -ne $null) -or 
                                                        ($_.DeviceDetail.OperatingSystem -ne $null) -or 
                                                        ($_.DeviceDetail.Browser -ne $null) )
                                                } | Select -Exp DeviceDetail -First $ref)

                $baseUA += ($user.Logs | Where { #($BadProtocols -notcontains $_.ClientAppUsed) -and 
                                                      ($_.Location.State -eq $baseState.Name)  -and 
                                                      ( ($_.DeviceDetail.DisplayName -ne $null) -or 
                                                        ($_.DeviceDetail.OperatingSystem -ne $null) -or 
                                                        ($_.DeviceDetail.Browser -ne $null) )
                                                } | Select userAgent -First $ref)

            } 

            $baseDevices = @($baseDevices | Where { $_ -ne $null } | Select -Unique)
            $baseUA = @($baseUA | Where { $_ -ne $null } | Select -Unique)
        
            # Get trusted/registered devices
            #$baseDevices += ($user.Logs | Where { ($baseDevices -notcontains $_.DeviceDetail) -and 
            #                                      ($_ | Select -Exp DeviceDetail | Where TrustType -ne $null) } | 
            #                                        Group-Object DeviceDetail | Sort Count -Descending | Select Name)
        }

        Write-Debug "########"
        #Write-Debug ($baseDevices | Out-String)

        #$baseDevices = ($baseDevices | Group-Object Name | Sort Count -Descending | Select Name)
        Write-Debug ("Total baseDevices: " + ($baseDevices | Measure-Object).Count)
        Write-Debug ($baseDevices | Out-String)


        # Fullfill empty device
        $emptyDevices | % { 
                        $_.DeviceDetail.Browser = $_.ClientAppUsed
                        $_.DeviceDetail.OperatingSystem = $_.ClientAppUsed
                        #$_.DeviceDetail.OperatingSystem = $_.AppDisplayName
                    }
        #########################################################################################################
        #Write-Host ($user.Logs | Where { $_ | Select -Exp DeviceDetail | Where Browser -eq "IE 11.0" } )
        #########################################################################################################

        # Identify risk logs
        if(($user.Logs | Measure-Object).Count -le $forceRisk) {
            $riskLogs = $user.Logs | Where { 
                (($_.MfaDetail -eq $null) -or $inMFA) -and 
                ($whiteState -notcontains $_.Location.State)
            }
        } else {
            $riskLogs = $user.Logs | Where { 
                #(($baseDevices -notcontains $_.DeviceDetail) -and ($_.MfaDetail -eq $null)) -or (($baseState.Name -ne ($_.Location.State) -and ($baseDevices -notcontains $_.DeviceDetail) -and ($_.MfaDetail -eq $null)) )
                #($baseDevices -notcontains $_.DeviceDetail) -and
                (($baseDevices -notcontains $_.DeviceDetail) -and ($baseIP.Name -notcontains $_.IpAddress) ) -and
                (($_.MfaDetail -eq $null) -or $inMFA) -and 
                ($_.IpAddress -notmatch $whiteIP) -and 

                ( ( ($baseState.Name -notcontains $_.Location.State) -and 
                        ($whiteState -notcontains $_.Location.State) ) -or
                        #($whiteState -notcontains $_.Location.State) ) -or
                ($badCountries -contains $_.Location.CountryOrRegion))
            }
        }

        # Most obvious signs: 
        # - Multiple countries = redflag
        if($hopCount -gt $HopsLimit -and ($riskLogs | Measure-Object).Count -gt 0) {
            $user.Compromised = $true
            $user.CompReason = " # Countries Hopper (Multiple)"
        }
    }

    #Write-Debug ($riskLogs | Out-String)
    Write-Debug ("Total logs: " + $user.Logs.Count)
    Write-Debug ("Risk logs: " + ($riskLogs | Measure-Object).Count | Out-String)
    

    $user | Add-Member -MemberType NoteProperty -Name BaseIP -Value $baseIP
    $user | Add-Member -MemberType NoteProperty -Name BaseDevices -Value $baseDevices
    $user | Add-Member -MemberType NoteProperty -Name BaseUA -Value $baseUA
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


    # Proxy detection, more proxy than HopsThreshold is redflag
    # Using proxycheck.io first
    $user.RiskLogs | Select -Unique IpAddress | % { $ips += "$($_.IpAddress)," }
    $proxyRisk = getProxyRisk $ProxyTable $ips
    Write-Debug "Proxy Risk: $($proxyRisk)"
    if(($proxyRisk -gt $HopsLimit) -or
         # If a user is not in active groups, higher risk
         (($proxyRisk -ge 1) -and (!$activeGroups.Contains($user.LocalGroup) -or ($user.Logs | Measure-Object).Count -lt $forceRisk ) ) ) {
        $user.Compromised = $true
        $user.CompReason = " # Proxied/Bad VPN Connections ($($proxyRisk)) #1"
    }


    if(!$user.Compromised) {

        # Group (success) RiskLogs into group by IP, then select the first and oldest log of each IP
        $RiskByIP = $user.RiskLogs | Group IpAddress
        $oldestRiskbyIP = @()
        $RiskByIP | % { $oldestRiskbyIP += ($_.Group | Sort CreatedDateTime -Descending | Select -First 1)} 


        # Extract countries from risk logs, exclude baseCountry
        $Hops = ($oldestRiskbyIP | ? {$_.Location.CountryOrRegion -notin $user.baseCountry.Name} | Group {$_.Location.CountryOrRegion})
        Write-Debug ("Total Hops: " + ($Hops | Out-String))
        # - Non-active users with logs from more than 1 country and it's not from VPN
        $Hops | % {
            $riskTime = $_.Group.CreatedDateTime
            $prevSafe = $user.Logs | Where { ($_.CreatedDateTime -lt $riskTime) -and ($_.Location.CountryOrRegion -in $user.baseCountry.Name) } | Select -First 1 CreatedDateTime
            if($prevSafe) {
                $timeSpan = New-TimeSpan $prevSafe.CreatedDateTime $riskTime
                }

            #Write-Debug ($timeSpan | Out-String)

            $HopType = getProxyType $ProxyTable "$($_.Group.IpAddress)"
            #Write-Host $_.Group.IpAddress $HopType
            if(( ($HopType.type -ne "VPN" -and ($Hops | Measure-Object).Count -gt 1) -or
                 ($HopType.type -ne "VPN" -and $timeSpan.TotalDays -lt 1) ) -and
                # Uncomment the following line to enforce only on non-active users (less aggressive)
                #!$activeGroups.Contains($user.LocalGroup) -and 
                !$user.Compromised) { 
                    $user.Compromised = $true
                    #$user.CompReason = " # Countries Hopper (Non-active User)"
                    $user.CompReason = " # Countries Hopper #2"
            }
        }

    }

    if(!$user.Compromised) {
    
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
        if($f) { $samples = $samples * 1.2}
        $failedLogs = Get-AzureADAuditSignInLogs -All:$true -Filter $filter -Top $samples
        Write-Debug $filter
        #Write-Host ($failedlogs | Out-String)
        Write-Debug ($failedlogs | Measure-Object).Count

        # Fullfill empty Location logs to reduce false positive
        $failedLogs | Where { $_ | Select -Exp Location | Where CountryOrRegion -eq $null } |  % { 
            #Write-Host $_.IpAddress -ForegroundColor Red
            $ipLoc = getIPLocation $IPTable $_.IpAddress
            $_.Location.City = $ipLoc.city
            $_.Location.State = $ipLoc.region
            $_.Location.CountryOrRegion = $ipLoc.country
            }

        # Password-spray/bruteforce/proxy detection
        $proxyCount = 0;
        for($i=0; $i -le ($oldestRiskbyIP | Measure-Object).Count-1; $i++) {
            $current = $oldestRiskbyIP[$i].CreatedDateTime
            $next = $oldestRiskbyIP[$i+1].CreatedDateTime
            if($i -eq ($oldestRiskbyIP | Measure-Object).Count-1) {
                $prevSafe = $user.Logs | Where { ($_.CreatedDateTime -lt $oldestRiskbyIP[$i].CreatedDateTime) -and ($_.Location.CountryOrRegion -in $user.baseCountry.Name) } | Select -First 1 CreatedDateTime
                if($prevSafe) {
                    $next = $prevSafe.CreatedDateTime
                } else { 
                    $next = (Get-Date $oldestRiskbyIP[$i].CreatedDateTime).AddDays(-3).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ")
                }
                #Write-Host $lastset $next
                if($lastset -gt $next) {
                    #$next = $lastset
                    $next = $current
                }
                # If ForceMode is ON, get failed logs from within the last 7 days from the last success sign-in to reduce false positive
                #if($f) { $next = (Get-Date $oldestRiskbyIP[$i].CreatedDateTime).AddDays(-7).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ") }
            }

            # Get failed sign-in logs in this time span, exclude logs from the same baseState or baseDevices
            $prevFailed = ($failedLogs | Where {
                ($_.CreatedDateTime -le $current -and $_.CreatedDateTime -gt $next) -and 
                ($user.baseDevices -notcontains $_.DeviceDetail) -and
                # + OR statement = more aggressive
                (($_.Location.State -ne $user.BaseState.Name) )#-or ($user.BaseIP -notcontains $_.IpAddress));
                
                } | Group IpAddress)

            Write-Debug ($oldestRiskbyIP[$i].IpAddress + " # " + $current + " -> " + $next + " # " + $oldestRiskbyIP[$i+1].IpAddress)    
            #Write-Debug ("Failed attempts " + ($prevFailed | Out-String))
            Write-DeBug (($prevFailed | Measure-Object).Count)
        
            # Multiple failed attempts follow by a successful sigin
            if((($prevFailed | Measure-Object).Count -gt $HopsLimit) -or
                 # If a user is not in active groups, higher risk
                 ( (($prevFailed | Measure-Object).Count -ge 1) -and 
                    !$activeGroups.Contains($user.LocalGroup) -and 
                    ($user.Logs | Measure-Object).Count -lt $forceRisk)
                 ) {
                $user.Compromised = $true
                $user.CompReason = " # Password-spray/Brute-force"
                Break
            }

            # If user has insufficient logs, treat them all as risk and run additional IP check using ip2proxy.com
            # Because of the budget constraint, this only run on users with fewer logs.
            if($user.RiskLogs.Count -le $forceRisk -and !$user.Compromised -and ($oldestRiskbyIP[$i].Location.CountryOrRegion -ne $user.baseCountry.Name) ) {
                $IPType = getProxyType2 $ProxyTable $oldestRiskbyIP[$i].IpAddress
                Write-DeBug $IPType
                $isProxy = (($IPType.isProxy -eq "YES" -and $IPType.proxyType -ne "VPN") -or ($IPType.Proxy -eq "yes" -and $IPType.Type -ne "VPN"))
                if($isProxy) { $proxyCount++ }
                if(($proxyCount -gt $HopsLimit) -or
                     # If a user is not in active groups, higher risk
                     (($proxyCount -ge 1) -and !$activeGroups.Contains($user.LocalGroup) ) ) {
                    $user.Compromised = $true
                    $user.CompReason = " # Proxied Connections ($($proxyCount)) #2"
                    Break
                }
            }
        }
    }


    return $user
}


# Check if users have any InboxRules created during the risk logs timespan
function getAuditLogs {
param(
    [Parameter(Mandatory)]
    [PSObject]$user,
    [Parameter()]
    [int]$samples = $null, # Reserved
    [Parameter()]
    [switch]$f # Reserved
    )

    if(($user.RiskLogs | Measure-Object).Count -gt 0) {
        Write-Progress -Activity "Getting Audit Logs.." -CurrentOperation ("Please wait.. ")
        $StartDate = $user.RiskLogs | Sort CreatedDateTime | Select -First 1 CreatedDateTime
        #$AuditLogs = Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -Operations @('New-InboxRule', 'Set-InboxRule') -UserIds $user.Email
        $AuditLogs = (Search-UnifiedAuditLog -StartDate ($StartDate.CreatedDateTime) -EndDate (Get-Date) `
                            -Operations $AuditOperations -UserIds $user.Email) |
                        Select AuditData 
        #Write-Host ($AuditLogs.AuditData | Out-String) -ForegroundColor Red 
        if($AuditLogs) {
            $AuditLogs = $AuditLogs.AuditData | ConvertFrom-Json

            $user | % {
                $UserRules = ($AuditLogs | Where UserId -eq $_.Email)
                #Write-Host ($UserRules | Out-String) -ForegroundColor Red 
                $_ | Add-Member -MemberType NoteProperty -Name AuditLogs -Value $UserRules

            }
        }

    }

    return $user
}



function analyzeAuditLogs {
param(
    [Parameter(Mandatory)]
    [PSObject]$user,
    [Parameter()]
    [int]$samples = $null, # Reserved
    [Parameter()]
    [switch]$f # Reserved
    )

    $user | % {
        $tmp = $_
        if(($_.AuditLogs | Measure-Object).Count -gt 0) {
        $badKeysFound = 0
        $dead = $false
            $_.AuditLogs.Parameters | Where { $RiskRules -contains $_.Name } | % {
                if($_.Name -in @("SubjectOrBodyContainsWords",
                    "SubjectContainsWords","FromAddressContainsWords")) {
                    $extract = $_.Value -split ";"
                    #Write-Host $extract -ForegroundColor Red
                    #Write-Host $badKeys -ForegroundColor Yellow
                    #Write-Host ($extract | Where { $badKeys -contains $_ })
                    $badKeysFound = ($extract | Where { $badKeys -contains $_ } | Measure-Object).Count
                    #Write-Host $badKeyFound
                }

                if($_.Name -eq "FromAddressContainsWords" -and $_.Value -eq "@") {
                    $dead = $true
                }

                if($_.Name -eq "DeleteMessage" -and $_.Value -eq $true -and 
                   $badKeysFound -gt 2 -or $dead){                     
                    $tmp.Compromised = $true
                    $tmp.CompReason += " # Malicious InboxRules"
                    $dead = $false
                }

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
    Write-Progress -Activity $username -CurrentOperation ("Init user.. ")
    Write-Progress -Activity $username -CurrentOperation ("Init user.. " + (Measure-Command {$user = getLocalAD $user }) )
    Write-Progress -Activity $username -CurrentOperation ("Getting AzureAD logs.. ")
    Write-Progress -Activity $username -CurrentOperation ("Getting AzureAD logs.. " + (Measure-Command {$user = getAzureLogs $user -samples $samples -f:$f }) )
    Write-Progress -Activity $username -CurrentOperation ("Identifying risk logs.. ")
    Write-Progress -Activity $username -CurrentOperation ("Identifying risk logs.. " + (Measure-Command {$user = getRiskLogs $user -samples $samples -f:$f }) )
    Write-Progress -Activity $username -CurrentOperation ("Analyzing risk logs.. ")
    Write-Progress -Activity $username -CurrentOperation ("Analyzing risk logs.. " + (Measure-Command {if(!$user.Compromised -and ($user.RiskLogs | Measure-Object).Count -gt 0) { $user = analyzeRisks $user -samples $samples -f:$f } }) )
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
        </style>
        <body>
        <div class='container-fluid'>
            <div class='h1 text-primary card-header font-weight-bold px-1'>
              Nyanalyzer Report
            </div>
            <div class='h5 font-italic font-weight-light px-1 mb-4'>Date: $((Get-Date).ToString('MM-dd-yyyy hh:mm:ss tt'))</div>
        </div>
        <div class='container-fluid mb-5'>
          <div class='row border border-light py-1'>
            <div class='col-2'>Total number of user(s) analyzed</div>
            <div class='col'><span class='badge badge-primary'>$(($user | Measure-Object).Count)</span></div>
            <div class='w-100'></div>
            <div class='col-2'>Compromised user(s)</div>
            <div class='col'><span class='badge badge-danger'>
                $(($user | Where {$_.Compromised -eq $true } | Measure-Object).Count)</span> 
                $( $user | Where {$_.Compromised -eq $true } | % { 
                        $str += "<a href='#$(($_.Email).Split("@")[0] )_head'>" + $_.Email + "</a>, " }; 
                        if($str) {
                            $str = $str.TrimEnd(", "); 
                            $str
                        } )
                $($str = '')
            </div>
            <div class='w-100'></div>
            <div class='col-2'>Risky user(s)</div>
            <div class='col'><span class='badge badge-warning'>
                $(($user | Where { $_.Compromised -ne $true -and ($_.RiskLogs | Measure-Object).Count -gt 0 } | Measure-Object).Count)</span>
                $($user | Where { $_.Compromised -ne $true -and ($_.RiskLogs | Measure-Object).Count -gt 0 } | % { 
                        $str += "<a href='#$(($_.Email).Split("@")[0] )_head'>" + $_.Email + "</a>, " }; 
                        if($str) {
                            $str = $str.TrimEnd(", "); 
                            $str
                        } )
                $($str = '')
            </div>
          </div>
        </div>
        "
        

    ($users | Sort Compromised, { ($_.RiskLogs | Measure-Object).Count},{ ($_.Logs | Measure-Object).Count} -Descending ) | % {

        $html += "<div class='container-fluid mb-5'>"    

        if($_.Compromised) { $riskhead = "<div id='$(($_.Email).Split("@")[0] )_head' class='button btn-danger text-white py-1 px-1 font-weight-bold border border-secondary'> $($_.Email) # COMPROMISED $($_.CompReason)</div>" }
        elseif ($_.RiskLogs -ne $null) { $riskhead = "<div id='$(($_.Email).Split("@")[0] )_head' class='button btn-warning text-danger py-1 px-1 font-weight-bold border border-secondary'>$($_.Email) $($_.CompReason)</div>"}
        
        if(($_.RiskLogs | Measure-Object).Count -gt 0 -or $_.Compromised) {
            $html += "<link rel='stylesheet' href='https://cdn.datatables.net/1.10.21/css/jquery.dataTables.min.css'>
                      <script src='https://cdn.datatables.net/1.10.21/js/jquery.dataTables.min.js'></script>"
            $html += $riskhead
            $html += $_ | Select @{Name='#Email';Expression={$_.Email};}, 
                                 @{Name='#Group';Expression={$_.LocalGroup};},
                                 @{Name='#Last Set';Expression={($_.Lastset)};}, 
                                 @{Name='#VPN User';Expression={ if($_.VPN) { $vcolor = "#9c0000"}; "<div style='color: $($vcolor); font-weight: bold;'>$($_.VPN)</div>" };}, 
                                 @{Name='#Logs';Expression={$_.Logs.Count};}, 
                                 @{Name='#RiskLogs';Expression={($_.RiskLogs | Measure-Object).Count};}, 
                                 @{Name='#BaseIP';Expression={ $_.BaseIP.Name | % {
                                                                                  "<div class='row border-bottom w-100 ml-0'><span class='font-weight-bold'>"
                                                                                  $_
                                                                                  "</span></div>" 
                                                                                 }};}, 
                                 @{Name='#BaseDevices';Expression={ "<div class='table-md my-x w-100'>"
                                                                            $_.BaseDevices | % {
                                                                            "<div class='row border-bottom w-100 ml-0'>"
                                                                                $_.PSObject.Properties | %  {
                                                                                    if($_.Name -notin @("IsCompliant","IsManaged")){
                                                                                        if($_.Name -eq "DeviceId") { $col = "col-3" }
                                                                                        else { $col = "col" }
                                                                                     "<div class='$($col) px-0 mx-0'><div class='col px-0 text-left d-inline'>" + $_.Name + ":</div>
                                                                                     <div class='col text-right font-weight-bold d-inline'>" + $_.Value + "</div></div>"
                                                                                    }
                                                                                }
                                                                            "</div>"
                                                                            }
                                                                            "</div>"
                                                                          };},
                                 @{Name='#UserAgent';Expression={ "<div class='table-md my-x w-100'>"
                                                                            $_.BaseUA | % {
                                                                            "<div class='row border-bottom w-100 ml-0'>"
                                                                                $_.userAgent
                                                                            "</div>"
                                                                            }
                                                                            "</div>"
                                                                          };},
                                                                                                                    
                                 @{Name='#BaseState';Expression={ "<span class='font-weight-bold'>" + (($_.BaseState.Name | Out-String) -replace "`n", " # ") + "</span>"};}, 
                                 @{Name='#BaseCountry';Expression={ "<span class='font-weight-bold'>" + (($_.BaseCountry.Name | Out-String) -replace "`n", " # ") + "</span>"};} |
                                 ConvertTo-Html -Fragment -As List
            $html = $html -replace "<td>#","<td style='width:15%'>"
            $html += "<div class='container-fluid float-right px-0'>"
            if(($_.RiskLogs | Measure-Object).Count -gt 0) {

                $html += "
                            <button class='btn btn-primary btn-sm mb-1 font-weight-bold float-right ml-1' type='button' data-toggle='collapse' 
                            data-target='#$(($_.Email).Split('@')[0] )' aria-expanded='false' aria-controls='$(($_.Email).Split('@')[0] )'>
                            View $($_.Email)'s Risky Logs <span class='badge badge-danger'>$(($_.RiskLogs | Measure-Object).Count)</span></button>
                         "
            }

            if(($_.AuditLogs | Measure-Object).Count -gt 0) {
                $html += "
                            <button class='btn btn-warning text-danger btn-sm mb-1 font-weight-bold float-right mx-1' type='button' data-toggle='collapse'
                            data-target='#$(($_.Email).Split('@')[0] )_AuditLogs' aria-expanded='false' aria-controls='$(($_.Email).Split('@')[0] )_AuditLogs'>
                            View $($_.Email)'s Audit Logs <span class='badge badge-danger'>$(($_.AuditLogs | Measure-Object).Count)</span></button>
                         "
            }
            $html += "</div>"

            if(($_.RiskLogs | Measure-Object).Count -gt 0) {
                $html2 += "<div id='$(($_.Email).Split('@')[0] )' class='collapse'>"
                $html2 += ConvertTo-HTMLTable ($_.RiskLogs | Select CreatedDateTime, UserDisplayName, UserPrincipalName, AppDisplayName, `
                            @{Name="IpAddress"; Expression={ 
                                    if($ProxyTable[$_.IpAddress].isProxy -eq "YES" -or $ProxyTable[$_.IpAddress].Proxy -eq "yes") 
                                    { $_.IpAddress = "<span class='text-danger font-weight-bold'>$($_.IpAddress) 
                                                    ($($ProxyTable[$_.IpAddress].ProxyType)$($ProxyTable[$_.IpAddress].Type)) 
                                                    <br>$($ProxyTable[$_.IpAddress].'attack history')</span>" }
                                    $_.IpAddress } },
                            ClientAppUsed, @{Name='Device'; Expression={ "<div class='table px-0' style='width:200px'>"
                                                                                    $_.DeviceDetail.PSObject.Properties | % {
                                                                                        if($_.Value) {
                                                                                        "<div class='row border-bottom px-0 mx-0'>
                                                                                         <div class='col px-0 d-inline'>" + $_.Name + ":</div> 
                                                                                         <div class='col-8 px-0 text-right font-weight-bold d-inline'>" + $_.Value + "</div>
                                                                                         </div>"
                                                                                        }
                                                                                    }
                                                                                    "</div>"
                                                                                  };
                                                                               },
                                @{Name='Location'; Expression={ "<div class='table px-0' style='width:120px'>"
                                                                                    $_.Location.PSObject.Properties | % {
                                                                                        if($_.Value) {
                                                                                        "<div class='row border-bottom px-0 mx-0'>
                                                                                         <div class='col px-0 d-inline'>" + $_.Name + ":</div> 
                                                                                         <div class='col-10 px-0 text-right font-weight-bold d-inline'>" + $_.Value + "</div>
                                                                                         </div>"
                                                                                        }
                                                                                    }
                                                                                    "</div>"
                                                                                  };
                                                                               }, 
                                IsInteractive, ResourceDisplayName, RiskDetail, 
                                @{Name='RiskAg';Expression={$_.RiskLevelAggregated};}, 
                                @{Name='RiskRealtime';Expression={$_.RiskLevelDuringSignIn};}, RiskState)

                $html2 += "</div>"
                $html += $html2 -replace "<table", "<table id='$(($_.Email).Split('@')[0] )_table'"
                $tablelist += "
                       `$('#$(($_.Email).Split('@')[0] )_table').DataTable({
                       `'order': [[0,'desc']]});
                       `$('.dataTables_length').addClass('bs-select');"
            }
            

            if(($_.AuditLogs | Measure-Object).Count -gt 0) {
                $html3 += "<div id='$(($_.Email).Split('@')[0] )_AuditLogs' class='collapse'>"
                $html3 += ConvertTo-HTMLTable ($_.AuditLogs | Select CreationTime, UserId, Operation,
                                                                      @{Name='Content'; Expression={ "<div class='container'>"
                                                                            if($_.Parameters) {
                                                                                $_.Parameters | % {
                                                                                    $warn = ""
                                                                                    if($RiskRules -contains $_.Name) { $warn = "text-danger font-weight-bold" }
                                                                                    "<div class='row table-striped border-bottom $warn'>" +`
                                                                                    "<div class='col-2 pl-1'>" + $_.Name + "</div>
                                                                                     <div class='col text-right pr-1'>" + $_.Value + "</div>" + `
                                                                                    "</div>"
                                                                                }
                                                                            } else {
                                                                                "<div class='row px-0'>"
                                                                                $_.ObjectId
                                                                                "</div>"
                                                                            }
                                                                            "</div>"
                                                                          };
                                                                       },   
                                                                      ClientIP, Id)
                $html3 += "</div>"
                $html += $html3 -replace "<table", "<table id='$(($_.Email).Split('@')[0] )_AuditLogs_table'"
                $tablelist += "                
                       `$('#$(($_.Email).Split('@')[0] )_AuditLogs_table').DataTable({
                       `'order': [[0,'desc']]});
                       `$('.dataTables_length').addClass('bs-select');"
            }

            $html2 = $html3 = ""
        } else {
            $html += "<a class='btn-secondary' data-toggle='collapse' href='#$(($_.Email).Split('@')[0] )' role='button' aria-expanded='false' aria-controls='$(($_.Email).Split('@')[0] )'>
            <div id='$(($_.Email).Split("@")[0] )_head' class='button btn-secondary text-success py-1 px-1 font-weight-bold border border-secondary'>$($_.Email)</div></a>
            <div id='$(($_.Email).Split('@')[0] )' class='collapse'>"
            $html += $_ | Select @{Name='#Email';Expression={$_.Email};}, 
                                 @{Name='#Group';Expression={$_.LocalGroup};},
                                 @{Name='#Last Set';Expression={($_.Lastset)};}, 
                                 @{Name='#VPN User';
                                    Expression={ 
                                        if($_.VPN) { $vcolor = "#9c0000"}; "<div style='color: $($vcolor); font-weight: bold;'>$($_.VPN)</div>" };}, 
                                 @{Name='#Logs';Expression={$_.Logs.Count};},
                                 @{Name='#RiskLogs';Expression={($_.RiskLogs | Measure-Object).Count};}, 
                                 @{Name='#BaseIP';Expression={ $_.BaseIP.Name | % {
                                                                                  "<div class='row border-bottom w-100 ml-0'><span class='font-weight-bold'>"
                                                                                  $_
                                                                                  "</span></div>" 
                                                                                 }};}, 
                                 @{Name='#BaseDevices';Expression={ "<div class='table-md my-x w-100'>"
                                                                            $_.BaseDevices | % {
                                                                            "<div class='row border-bottom w-100 ml-0'>"
                                                                                $_.PSObject.Properties | %  {
                                                                                    if($_.Name -notin @("IsCompliant","IsManaged")){
                                                                                        if($_.Name -eq "DeviceId") { $col = "col-3" }
                                                                                        else { $col = "col" }
                                                                                     "<div class='$($col) px-0 mx-0'><div class='col px-0 text-left d-inline'>" + $_.Name + ":</div>
                                                                                     <div class='col text-right font-weight-bold d-inline'>" + $_.Value + "</div></div>"
                                                                                    }
                                                                                }
                                                                            "</div>"
                                                                            }
                                                                            "</div>"
                                                                          };}, 
                                 @{Name='#UserAgent';Expression={ "<div class='table-md my-x w-100'>"
                                                                            $_.BaseUA | % {
                                                                            "<div class='row border-bottom w-100 ml-0'>"
                                                                                $_.userAgent
                                                                            "</div>"
                                                                            }
                                                                            "</div>"
                                                                          };},

                                 @{Name='#BaseState';Expression={ "<span class='font-weight-bold'>" + (($_.BaseState.Name | Out-String) -replace "`n", " # ") + "</span>"};}, 
                                 @{Name='#BaseCountry';Expression={ "<span class='font-weight-bold'>" + (($_.BaseCountry.Name | Out-String) -replace "`n", " # ") + "</span>"};} |
                                 ConvertTo-Html -Fragment -As List
            $html = $html -replace "<td>#","<td style='width:15%'>"
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
                    Write-Progress -Activity "$item" -Status "Progress: $i / $($totalItems.Count)" -PercentComplete (($i / $totalItems.Count)  * 100)
                    $users += (NyanLogs -username $item -samples $samples -f:$f)
                    #Write-Debug ($tmp | Out-String)
                }

            } else { $username.Split(",") | % { $users += (NyanLogs -username $_ -samples $samples -f:$f) } }
            
            if(!$isDebug) { Clear-Host; printNyan }

            if($AuditLogOn) { 
                getAuditLogs $users -samples $samples -f:$f 
                analyzeAuditLogs $users -samples $samples -f:$f 
            }

            Summary $users
            exportReport $users
            sendReport

            if(!$killEXO -and !$keep -and $AuditLogOn) {
                $dEXO = Read-Host "Disconnect EXO? (y/N): "
            }
            
            if(@("y","Y").Contains($dEXO) -or $killEXO) {
                    Disconnect-ExchangeOnline -Confirm:$false
                    Write-Debug "EXO disconnected."
            }

        #} catch { 
        #    $ErrorMessage = $_.Exception.Message
        #    $FailedItem = $_.Exception.ItemName
        #    Write-Host $ErrorMessage
        #    Disconnect-ExchangeOnline -Confirm:$false
        #}
    } else {
        Write-Host "Usage: ./nyanalyzer.ps1 <input file OR a single email> [number of log samples] [-f] [-debug]
        # The script accepts up to 6 parameters
        # The first one is required: could be a list of emails in file, or a single email or an inline list of users `"user1, user2`"
        # The second one is optional: define the number of log sample you want to analyze
        # -f: force the script to get logs from the last 90 days
        # -debug: debug mode
        # -killEXO switch: kill EXO connection without asking, reserved
        # -keep switch: keep EXO connection without asking, reserved
        " -ForegroundColor Yellow
    }

    # DEBUG here
    if($isDebug) {
        Write-Debug ($users.baseCountry | Out-String)
        Write-Debug ($users.baseIP | Out-String)
        #Write-Debug ($users.baseUA | Out-String)
        #Write-Debug ($user.Logs | Out-String)      
        #Write-Debug ($IPTable | Out-String)

    }
    
}

#try {
    $runtTime = (Measure-Command { Main })
    $runtTime | select @{n="Runtime";e={$_.Minutes,"Minutes",$_.Seconds,"seconds",$_.Milliseconds,"ms" -join " "}}
#} catch { 
#    $ErrorMessage = $_.Exception.Message
#    $FailedItem = $_.Exception.ItemName
#    Write-Host $ErrorMessage
#}