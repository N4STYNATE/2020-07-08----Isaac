Clear-Host

#Elevate to Admin if not already 
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) 
{    
$arguments = "& '" + $myinvocation.mycommand.definition + "'" 
Start-Process powershell -Verb runAs -ArgumentList $arguments \
Break 
} 

#Cache Credentials 
$global:domain = "OKLAND.COM"
$oklandUser = Read-Host -Prompt "Enter First.Last" 
$userName = "$domain\$oklandUser"
$password = Read-Host -Prompt "Enter password for $userName" -AsSecureString
$global:credential = New-Object System.Management.Automation.PSCredential($userName,$password)
Write-Host "Checking Domain"
$host.UI.RawUI.WindowTitle = "Domain Check"
$domainCurrent = (gwmi WIN32_ComputerSystem).Domain
$domainOkland = "Okland.com"

function onDomain {
        write-host "Connected to Okland.com... Please wait."
        Start-Sleep -Second 3
        runAll
}

function addDomain {
        Clear-Host
        $host.UI.RawUI.WindowTitle = "Adding to Okland Domain"
        write-host "Not on Okland Domain... Adding"

        #Add Jserver to OKLAND\Domain
        $Server = Read-Host -Prompt 'Input Jsever name'
        Write-Host $Server',' $domain
        Pause 
        Add-Computer -ComputerName $Server -DomainName $domain -Credential $credential
}

Function runAll {
    $host.UI.RawUI.WindowTitle = "Running Jserver Setup"
    write-host "Running Jserver Setup"

    #Connect to network files
    net use \\azadmin\itapps\commonApps /user:$credential
    Start \\azadmin\itapps\commonApps
    #Disable IE Security
    Write-Host "Disabling Internet Explorer Enhanced Security." -ForegroundColor Green  

        function Disable-InternetExplorerESC {
            $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
            $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
            Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force
            Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0 -Force
            Stop-Process -Name Explorer -Force
            Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green
        }
        function Enable-InternetExplorerESC {
            $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
            $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
            Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 1 -Force
            Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 1 -Force
            Stop-Process -Name Explorer
            Write-Host "IE Enhanced Security Configuration (ESC) has been enabled." -ForegroundColor Green
        }
        function Disable-UserAccessControl {
            Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000 -Force
            Write-Host "User Access Control (UAC) has been disabled." -ForegroundColor Green    
        }
        #Disable-UserAccessControl
        Disable-InternetExplorerESC

    #Install Roles and features

	#DFS Replication
Write-Host "DFS Replictaion Installing." -ForegroundColor Green
Install-WindowsFeature -Name FS-DFS-Replication -computerName $env:computername 

	#Telnet Client
Write-Host "Telnet Client Installing." -ForegroundColor Green
Install-WindowsFeature -Name Telnet-Client -computerName $env:computername

	#Bitlocker Drive Encryption
Write-Host "Bitlocker Installing." -ForegroundColor Green
Install-WindowsFeature -Name Bitlocker -computerName $env:computername 

	#File Server Resouce Manager
Write-Host "File Server Resource Manager Installing." -ForegroundColor Green
Install-WindowsFeature -Name FS-Resource-Manager -computerName $env:computername 

#Net Commands
Write-Host "NETSH commands running." -ForegroundColor Green
netsh int ip set global taskoffload=disabled
netsh interface tcp set global autotuninglevel=disabled
netsh interface tcp set global rss=disabled
netsh int tcp set global rss=disabled
netsh int tcp set global chimney=disabled

#Create User Accounts
Write-Host "Creating user accounts." -ForegroundColor Green
NET USER Administrator u8i9o0p- /add
NET USER Scanner Aa123456 /add

#Open Batch to set Password never expires
Write-Host "Opening batch." -ForegroundColor Green
Invoke-Item C:\cmd.bat


#Set Password Never Expire (Only server 2016+)
Set-LocalUser -Name "Administrator" -PasswordNeverExpires $true
Set-LocalUser -Name "Scanner" -PasswordNeverExpires $true

#Set SRMSVC to Manual
Write-Host "Changing SrmSvc to manual." -ForegroundColor Green
Set-Service -Name srmsvc -StartupType Manual

#Disable TCP/UDP checksum Offload
Write-Host "Disabling TDP/UDP Checksum Offload." -ForegroundColor Green
Disable-NetAdapterChecksumOffload -Name "*" -TcpIPv6
Disable-NetAdapterChecksumOffload -Name "*" -TcpIPv4
Disable-NetAdapterChecksumOffload -Name "*" -UdpIPv6
Disable-NetAdapterChecksumOffload -Name "*" -UdpIPv4


#Disable IPv6 on both Nics
Write-Host "Disabling IPv6 on NICS." -ForegroundColor Green
Disable-NetAdapterBinding -Name "Ethernet" -ComponentID ms_tcpip6
Disable-NetAdapterBinding -Name "Ethernet 2" -ComponentID ms_tcpip6

#Create File Folders
Write-Host "Creating file folders." -ForegroundColor Green
MD -Path 'C:\Shared Files\Scans'
MD -Path 'C:\Shared Files\Safety Videos'
MD -Path 'C:\Apps'

Write-Host "Copying files...." -ForegroundColor Green
Copy-Item "\\azadmin\itapps\commonApps\Scripts" "C:\Apps" -Container -Recurse -Verbose
Copy-Item "\\azadmin\itapps\apps\Safety Videos\Compressed\SafetyVideos\New Safety Orientation English compressed.mp4" "C:\Shared Files\Safety Videos"
Copy-Item "\\azadmin\itapps\apps\Safety Videos\Compressed\SafetyVideos\New Safety Orientation Spanish compressed.mp4" "C:\Shared Files\Safety Videos"

#Add users to groups
Write-Host "Adding users to groups." -ForegroundColor Green
NET localgroup "Administrators" "OKLAND\MIS" /add
NET localgroup "Remote Desktop Users" "OKLAND\MIS" /add
NET localgroup "Remote Desktop Users" "OKLAND\Domain Admins" /add
NET localgroup "Remote Desktop Users" "$env:computername\Administrator" /add

#Start Mirror Proccess 
Write-Host "Caching apps." -ForegroundColor Green
Invoke-Item "C:\Apps\Scripts\Mirror CommonApps to local apps.bat"

#Share Safety Videos to Everyone with Read Access
Write-Host "Sharing folders." -ForegroundColor Green
New-SmbShare -Name "Safety Videos" -Path "C:\Shared Files\Safety Videos"

#Share Scans with MIS(FullAccess), Domain Users(ChangeAccess), Local Scanner(ChangeAccess)
Write-Host "Sharing folders." -ForegroundColor Green
New-SmbShare -Name "Scans" -Path "C:\Shared Files\Scans" -FullAccess OKLAND\MIS
Grant-SmbShareAccess -Name "Scans" -AccountName "$env:computername\Scanner" -AccessRight Change -Force
Grant-SmbShareAccess -Name "Scans" -AccountName "OKLAND\Domain Users" -AccessRight Change -Force

#Set NIC 1 
Write-Host "Setting NIC 1 settings." -ForegroundColor Green
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses ("192.168.111.5","192.168.2.5")
netsh interface ipv4 set address name="Ethernet" static 192.168.16.5 255.255.248.0 192.168.16.1

#Enable Remote Access 
Write-Host "Enabling Remote Access." -ForegroundColor Green
Set-ItemProperty -Path "HKLM:System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
(Get-WmiObject -class Win32_TSGeneralSetting -Namespace root\cimv2\terminalservices -ComputerName "$env:computername" -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0)

#Stop Replication on Auto Recov
Write-Host "Changing Registry." -ForegroundColor Green
Set-ItemProperty -Path "HKLM:System\CurrentControlSet\Services\DFSR\Parameters" -Name "StopReplicationOnAutoRecovery" -Value 0
}


Function domainCheck {
    if( $domainCurrent -eq $domainOkland ){
        onDomain
    }
    else {
        addDomain
    }
}

domainCheck
