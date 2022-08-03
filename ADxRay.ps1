#requires -version 2
<#
.SYNOPSIS
Active Directory xRay Inventory

.DESCRIPTION
This Script is based and inspired on Sukhija Vika's 'Active Directory Health Check' script 
(https://gallery.technet.microsoft.com/scriptcenter/Active-Directory-Health-709336cd), the amazing Clint Huffman's 'Performance Analysis of Logs (PAL) tool' 
(https://github.com/clinthuffman/PAL) and Microsoft's Ned Pyle blogpost 'What does DCDIAG actually... do?'
https://blogs.technet.microsoft.com/askds/2011/03/22/what-does-dcdiag-actually-do/ 

.OUTPUTS
Details regarding the environment will be presented during the execution of the script. The log file will be created at: C:\AdxRay\ADXRay.log

.NOTES
Version:        5.6.6
Author:         Claudio Merola
Date:           08/03/2022

#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

param ($Clear,$JobTimeout=180)

write-host 'Starting ADxRay Script..' -ForegroundColor Green

# Version
$Global:Ver = '5.6'

$Global:SupBuilds = '10.0 (19042)','10.0 (19043)','10.0 (19044)'

$Global:Runtime = Measure-Command -Expression {

if ((Test-Path -Path C:\ADxRay -PathType Container) -eq $false) {New-Item -Type Directory -Force -Path C:\ADxRay}

$Global:report = ("C:\ADxRay\ADxRay_Report_"+(get-date -Format 'yyyy-MM-dd')+".htm") 
if ((test-path $report) -eq $false) {new-item $report -Type file -Force}
Clear-Content $report 

$Global:ADxRayLog = "C:\ADxRay\ADxRay.log"
if ((test-path $ADxRayLog) -eq $false) {new-item $ADxRayLog -Type file -Force}
Clear-Content $ADxRayLog 

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting ADxRay Script")
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting Data Catcher")
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Setting Error Action Preference")

$ErrorActionPreference = "silentlycontinue"


########################################################################################################## BEGIN OF FUNCTIONS ################################################################################################

###################################### HEADER FUNCTION ##########################################

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Selecting Script Option")
Write-Host ""
Write-Host "Select the desired option below:"
Write-Host ""
Write-Host "1)  " -NoNewline -ForegroundColor Magenta
write-host "Full Inventory" -ForegroundColor Yellow
Write-Host "2)  " -NoNewline -ForegroundColor Magenta
write-host "Forest Inventory" -ForegroundColor Yellow
Write-Host "3)  " -NoNewline -ForegroundColor Magenta
write-host "Domain Inventory" -ForegroundColor Yellow
Write-Host "4)  " -NoNewline -ForegroundColor Magenta
write-host "Only Collect Inventory Files" -ForegroundColor Yellow
Write-Host "5)  " -NoNewline -ForegroundColor Magenta
write-host "Process Collected Inventory Files" -ForegroundColor Yellow
Write-Host ""
[int]$Global:Option = read-host "( default 1 )"
if($Global:Option -eq 0){$Global:Option = 1}
Write-Host ""
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Option: "+$Global:Option+" Selected")

###################################### HAMMER FUNCTION ##########################################

function Hammer 
    {
        write-host 'Starting The Hammer..'
        Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting The Hammer!")
        Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Creating Hammer Folder")


        if ((Test-Path -Path C:\ADxRay\Hammer -PathType Container) -eq $false) {New-Item -Type Directory -Force -Path C:\ADxRay\Hammer}

        Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Killing current running Powershell job")

        Get-Job | Remove-Job

        Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Calling DCDiag")

        if($Clear.isPresent)
            {
                $Files = Get-ChildItem -path 'C:\ADxRay\Hammer\' 
                Foreach ($File in $Files)
                    {
                        remove-item -Path $File.FullName -Force
                    }
            }

        function HammerForest 
            {

                Write-Progress -activity 'Running Inventories' -Status "1% Complete." -CurrentOperation 'Triggering Forest Inventory..'

                Start-job -Name 'Diag' -scriptblock {dcdiag /e /s:$($args)} -ArgumentList $Forest.SchemaRoleOwner.Name | Out-Null

                Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting Active Directory RecycleBin Check")

                Start-job -Name 'RecycleBin' -ScriptBlock {if ((Get-ADOptionalFeature -Filter * | Where-Object {$_.Name -eq 'Recycle Bin Feature' -and $_.EnabledScopes -ne '' })) {'Enabled'}else{'Not Enabled'}} | Out-Null

                Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Duplicated SPNs check")

                Start-job -Name 'SPN' -scriptblock {setspn -X -F} | Out-Null

                Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting Trusts Inventory")

                Start-job -Name 'Trusts' -scriptblock {Get-ADtrust -Filter * -Server $($args) -ErrorAction SilentlyContinue -WarningAction SilentlyContinue } -ArgumentList $Forest.SchemaRoleOwner.Name | Out-Null

                Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting Domain Inventory")

                Write-Progress -activity 'Running Inventories' -Status "5% Complete." -CurrentOperation 'Triggering Domain Inventory..'

                $Global:SecGroups = @('Domain Admins','Schema Admins','Enterprise Admins','Server Operators','Account Operators','Administrators','Backup Operators','Print Operators','Domain Controllers','Read-only Domain Controllers','Group Policy Creator Owners','Cryptographic Operators','Distributed COM Users')

                Foreach ($zone in $Forest.ApplicationPartitions.Name)
                    {
                        Start-job -Name ('Zone_'+$zone) -scriptblock {Get-ADObject -Filter {Name -like '*..InProgress*'} -SearchBase $($args)} -ArgumentList $zone
                    }
            }

        function HammerDomain
            {

                Foreach ($Domain in $Global:Domains)
                    { 
                        start-job -Name ($Domain.Name+'_Inv') -scriptblock {Get-ADDomain -Identity $($args) -ErrorAction SilentlyContinue -WarningAction SilentlyContinue} -ArgumentList $Domain.Name | Out-Null

                        start-job -Name ($Domain.Name+'_SysVol') -scriptblock {Get-ChildItem  -path $($args) -Recurse | Where-Object -FilterScript {$_.PSIsContainer -eq $false} | Group-Object -Property Extension | ForEach-Object -Process {
                        New-Object -TypeName PSObject -Property @{
                            'Extension'= $_.name
                            'Count' = $_.count
                            'TotalSize (MB)'= '{0:N2}' -f ((($_.group | Measure-Object length -Sum).Sum) /1MB)
                            'TotalSize'    = (($_.group | Measure-Object length -Sum).Sum)
                            } } | Sort-Object -Descending -Property 'Totalsize'} -ArgumentList ('\\'+$Domain.Name+'\SYSVOL\'+$Domain.Name) | Out-Null

                        start-job -Name ($Domain.Name+'_GPOs') -scriptblock {Get-GPOReport -All -ReportType XML -Path ("C:\ADxRay\Hammer\GPOs_"+$args+".xml")} -ArgumentList $Domain.Name | Out-Null

                        start-job -Name ($Domain.name+'_Usrs') -scriptblock {dsquery * -filter sAMAccountType=805306368 -s $($args) -attr userAccountControl -limit 0} -ArgumentList $Domain.PdcRoleOwner.Name  | Out-Null

                        start-job -Name ($Domain.name+'_Comps') -scriptblock {dsquery * -filter sAMAccountType=805306369 -s $($args) -Attr OperatingSystem  -limit 0} -ArgumentList $Domain.PdcRoleOwner.Name  | Out-Null

                        start-job -Name ($Domain.name+'_GrpAll') -scriptblock {ForEach($grp in $($args[1])) {@{$grp = ((dsquery * -filter "(&(objectclass=group)(name=$grp))" -s $($args[0]) -attr member -limit 0).split(";") | Where-Object {$_ -like '*DC*'}).count}}} -ArgumentList $Domain.PdcRoleOwner.Name,$SecGroups  | Out-Null

                }

                Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting Domain Controllers Inventory")
            }        

        function HammerDC
            {

                Write-Progress -activity 'Running Inventories' -Status "10% Complete." -CurrentOperation 'Triggering Domain Controller Inventory..'

                Foreach ($DC in $Global:DCs) {

                #start-job -Name ($DC.Name+'_Evts') -scriptblock {(Get-EventLog -ComputerName $args -LogName Security -InstanceId 4618,4649,4719,4765,4766,4794,4897,4964,5124,1102).Count} -ArgumentList $DC.Name | Out-Null

                #start-job -Name ($DC.Name+'_EvtBackup') -scriptblock {Get-winevent -Filterhashtable @{logname='Microsoft-Windows-Backup/operational';ID=4} -ComputerName $($args[0])} -ArgumentList $DC.Name | Out-Null

                #start-job -Name ($DC.Name+'_BatchJobEvt') -scriptblock {(Get-EventLog -LogName Security -InstanceId 4624 -Message '*Logon Type:			4*' -ComputerName $args).Count} -ArgumentList $DC.Name | Out-Null

                #start-job -Name ($DC.Name+'_CleartxtEvt') -scriptblock {(Get-EventLog -LogName Security -InstanceId 4624 -Message '*Logon Type:			8*' -ComputerName $args).Count} -ArgumentList $DC.Name | Out-Null

                    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting Domain Controllers Inventory of: "+$DC.Name+'. On: '+$DC.Domain)

                    Start-job -Name ('Inv_'+$DC.Name) -ScriptBlock {
                    
                    $job = @()

                    $Inv = ([PowerShell]::Create()).AddScript({param($DomControl)Get-ADDomainController -Server $DomControl }).AddArgument($($args[0]))

                    $Software64 = ([PowerShell]::Create()).AddScript({param($DomControl)Invoke-Command -cn $DomControl -ScriptBlock {Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*}}).AddArgument($($args[0]))

                    $Software86 = ([PowerShell]::Create()).AddScript({param($DomControl)Invoke-Command -cn $DomControl -ScriptBlock {Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*}}).AddArgument($($args[0]))

                    $Feature = ([PowerShell]::Create()).AddScript({param($DomControl)Get-WindowsFeature -ComputerName $DomControl | Where-Object {$_.Installed -eq 'Installed'}}).AddArgument($($args[0]))

                    $HW = ([PowerShell]::Create()).AddScript({param($DomControl)Invoke-Command -cn $DomControl -ScriptBlock {systeminfo /fo CSV | ConvertFrom-Csv}}).AddArgument($($args[0]))

                    $HWBkp = ([PowerShell]::Create()).AddScript({param($DomControl)systeminfo /S $DomControl /fo CSV | ConvertFrom-Csv}).AddArgument($($args[0]))

                    $Backup = ([PowerShell]::Create()).AddScript({param($DomControl)repadmin /showbackup $DomControl}).AddArgument($($args[0]))

                    $NTP1 = ([PowerShell]::Create()).AddScript({param($DomControl)Invoke-Command -cn $DomControl -ScriptBlock {W32TM /query /status}}).AddArgument($($args[0]))

                    $NTP2 = ([PowerShell]::Create()).AddScript({param($DomControl)Invoke-Command -cn $DomControl -ScriptBlock {W32TM /query /configuration}}).AddArgument($($args[0]))

                    $HotFix = ([PowerShell]::Create()).AddScript({param($DomControl)Get-HotFix -ComputerName $DomControl | Sort-Object { [datetime]$_.InstalledOn },HotFixID -desc | Select-Object -First 1}).AddArgument($($args[0]))

                    $Proc = ([PowerShell]::Create()).AddScript({param($DomControl)(Get-CimInstance -Class Win32_ComputerSystem -ComputerName $DomControl).NumberOfLogicalProcessors}).AddArgument($($args[0]))

                    $FreeSpace = ([PowerShell]::Create()).AddScript({param($DomControl)(Get-Counter -counter "\LogicalDisk(*)\% Free Space" -ComputerName $DomControl).CounterSamples}).AddArgument($($args[0]))

                    $Spooler = ([PowerShell]::Create()).AddScript({param($DomControl)Get-CimInstance -ClassName Win32_Service -Filter "Name = 'Spooler'" -Property State,StartMode -ComputerName $DomControl}).AddArgument($($args[0]))

                    $GPResult = ([PowerShell]::Create()).AddScript({param($DomControl)Get-GPResultantSetOfPolicy -Computer $DomControl -ReportType Xml -Path ("C:\ADxRay\Hammer\RSOP_"+$DomControl+".xml")}).AddArgument($($args[0]))

                    $DNS = ([PowerShell]::Create()).AddScript({param($DomControl)Get-DnsServer -ComputerName $DomControl}).AddArgument($($args[0]))

                    $ldapRR = ([PowerShell]::Create()).AddScript({param($DomControl,$Dom)Get-DnsServerResourceRecord -ZoneName ('_msdcs.'+$Dom) -Name '_ldap._tcp.dc' -ComputerName $DomControl}).AddArgument($($args[0])).AddArgument($($args[1]))

                    $jobInv = $Inv.BeginInvoke()
                    $jobSW64 = $Software64.BeginInvoke()
                    $jobSW86 = $Software86.BeginInvoke()
                    $jobFeature = $Feature.BeginInvoke()
                    $jobHW = $HW.BeginInvoke()
                    $jobHWBkp = $HWBkp.BeginInvoke()
                    $jobBackup = $Backup.BeginInvoke()
                    $jobNTP1 = $NTP1.BeginInvoke()
                    $jobNTP2 = $NTP2.BeginInvoke()
                    $JobHotFix = $HotFix.BeginInvoke()
                    $jobProc = $Proc.BeginInvoke()
                    $jobFreeSpace = $FreeSpace.BeginInvoke()
                    $jobSpooler = $Spooler.BeginInvoke()
                    $jobGPResult = $GPResult.BeginInvoke()
                    $jobDNS = $DNS.BeginInvoke()
                    $jobLdapRR = $ldapRR.BeginInvoke()

                    $job += $jobInv
                    $job += $jobSW64
                    $job += $jobSW86
                    $job += $jobFeature
                    $job += $jobHW
                    $job += $jobHWBkp
                    $job += $jobBackup
                    $job += $jobNTP1
                    $job += $jobNTP2
                    $job += $JobHotFix
                    $job += $jobProc
                    $job += $jobFreeSpace
                    $job += $jobSpooler
                    $job += $jobGPResult
                    $job += $jobDNS
                    $job += $jobLdapRR

                    while ($Job.Runspace.IsCompleted -contains $false) {}

                    $InvS = $Inv.EndInvoke($jobInv)
                    $SW64S = $Software64.EndInvoke($jobSW64)
                    $SW86S = $Software86.EndInvoke($jobSW86)
                    $FeatureS = $Feature.EndInvoke($jobFeature)
                    $HWS = $HW.EndInvoke($jobHW)
                    $HWSBkp = $HWBkp.EndInvoke($jobHWBkp)
                    $BackupS = $Backup.EndInvoke($jobBackup)
                    $NTP1S = $NTP1.EndInvoke($jobNTP1)
                    $NTP2S = $NTP2.EndInvoke($jobNTP2)
                    $HotFixS = $HotFix.EndInvoke($jobHotFix)
                    $ProcS = $Proc.EndInvoke($jobProc)
                    $FreeSpaceS = $FreeSpace.EndInvoke($jobFreeSpace)
                    $SpoolerS = $Spooler.EndInvoke($jobSpooler)
                    $DNSS = $DNS.EndInvoke($jobDNS)
                    $ldapRRS = $ldapRR.EndInvoke($jobLdapRR)

                    $Inv.Dispose()
                    $Software64.Dispose()
                    $Software86.Dispose()
                    $Feature.Dispose()
                    $HW.Dispose()
                    $HWBkp.Dispose()
                    $Backup.Dispose()
                    $NTP1.Dispose()
                    $NTP2.Dispose()
                    $HotFix.Dispose()
                    $Proc.Dispose()
                    $FreeSpace.Dispose()
                    $Spooler.Dispose()
                    $GPResult.Dispose()
                    $DNS.Dispose()
                    $ldapRR.Dispose()

                    $DataServer = @{
                                    'Inventory' = $InvS;
                                    'Software_64' = $SW64S;
                                    'Software_86' = $SW86S;
                                    'Installed_Features' = $FeatureS.Name;
                                    'Hardware' = $HWS;
                                    'HardwareBkp' = $HWSBkp;
                                    'Backup' = $BackupS;
                                    'NTP_Status' = $NTP1S;
                                    'NTP_Config' = $NTP2S;
                                    'HotFix' = $HotFixS;
                                    'Processor' = $ProcS;
                                    'FreeSpace' = $FreeSpaceS;
                                    'Spooler' = $SpoolerS;
                                    'DNS' = $DNSS;
                                    'ldapRR' = $ldapRRS}

                    $DataServer

                    } -ArgumentList $DC.Name,$DC.Domain

                }

                Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Waiting Inventories Conclusion")
            }        

        function WaitJobs
            {

                $c = 0
                $WaitTime = get-date
                $WaitTime2 = get-date
                while (get-job | Where-Object {$_.State -eq 'Running'})
                    {
                        $jb = get-job
                        $c = (((($jb.count - ($jb | Where-Object {$_.State -eq 'Running'}).Count)) / $jb.Count) * 100)
                        $c = [math]::Round($c)
                        Write-Progress -activity 'Running Inventories' -Status "$c% Complete." -PercentComplete $c -CurrentOperation 'Waiting Inventories..'
                        if ((New-TimeSpan -Start $WaitTime2 -End (get-date)).TotalMinutes -ge 10)
                            {
                                Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Warn - Still Waiting for the following Inventory Jobs:")
                                foreach($jbb in ($jb | Where-Object {$_.State -eq 'Running'}))
                                    {
                                        Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Warn - Job: "+$jbb.Name)
                                    }
                                $WaitTime2 = get-date
                            }
                        if ((New-TimeSpan -Start $WaitTime -End (get-date)).TotalMinutes -ge $JobTimeout)
                            {
                                Get-Job | Stop-Job | Out-Null
                                Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Err - Timing Out Inventory Jobs")
                            }
                        Start-Sleep -Seconds 2
                    }
                Write-Progress -activity 'Running Inventories' -Status "100% Complete." -Completed

                Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - All Inventories are completed")
            
            }

        function ForestJob
            {

                write-host 'Inventories done..'
                write-host 'Starting to Process the Results..'
                Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting to Process Forest Inventory")

                $DuplicatedZones = @()
                $Global:Diag = Receive-Job -Name 'Diag' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                $RecycleBin = Receive-Job -Name 'RecycleBin' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                $SPN = Receive-Job -Name 'SPN' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                $Trusts = Receive-Job -Name 'Trusts' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

                Foreach ($zone in $Forest.ApplicationPartitions.Name)
                    {
                        $DuplicatedZones += receive-job -Name ('Zone_'+$zone) 
                    }

                if ((test-path 'C:\ADxRay\Hammer\Forest.xml') -eq $true) {remove-item -Path 'C:\ADxRay\Hammer\Forest.xml' -Force}

                $Trss = @()
                Foreach ($Trust in $Trusts)
                    {
                        $Trss += $Trust
                    }
                
                $SSPN = ($SPN | Select-String -Pattern ('duplicate SPNs')).ToString()

                $Fores = @{
                        'ForestName' = $Forest.Name;
                        'Domains' = $Forest.Domains.Name;
                        'RecycleBin' = $RecycleBin;
                        'ForestMode' = $Forest.ForestMode;
                        'GlobalCatalogs' = $Forest.GlobalCatalogs.Name;
                        'Sites' = $Forest.Sites.Name;
                        'Trusts' = $Trss;
                        'SPN' = $SSPN;
                        'DuplicatedDNSZones' = $DuplicatedZones.DistinguishedName
                    }

                Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Registering Forest XML File")

                $Fores | Export-Clixml -Path 'C:\ADxRay\Hammer\Forest.xml'

            }

        function DomainJob 
            {    

                Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting to Process Domain Inventory")
                Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting to Process Domains Details")

                Foreach ($Domain in $Global:Domains)
                    {

                        $InvDom = Receive-Job -Name ($Domain.Name+'_Inv') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                        $SysVolDom = Receive-Job -Name ($Domain.Name+'_SysVol') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                        $Usrs = Receive-Job -Name ($Domain.name+'_Usrs') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                        $Comps = Receive-Job -Name ($Domain.name+'_Comps') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                        $GrpAll = Receive-Job -Name ($Domain.name+'_GrpAll') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                        $GPOALL = Receive-Job -Name ($Domain.name+'_GPOs') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

                        Start-job -Name ($Domain.Name+'_job') -ScriptBlock {
                            if ((test-path ('C:\ADxRay\Hammer\Domain_'+$($args[0]).Name+'.xml')) -eq $true) {remove-item -Path ('C:\ADxRay\Hammer\Domain_'+$($args[0]).Name+'.xml') -Force}

                            $InvDom = $($args[2])
                            $SysVolDom = $($args[3])
                            $Usrs = $($args[4])
                            $Comps = $($args[5])
                            $GrpAll = $($args[6])
                            $GPOALL = $($args[7])

                            $att = @()
                            foreach ($UAC in $Usrs)
                                {
                                    $att += 1..26 | Where-Object {$UAC -bAnd [math]::Pow(2,$_)}
                                } 

                            $DomainTable = @{
                                    'Domain' = $($args[0]).name;
                                    'DNSRoot' = $InvDom.DNSRoot;
                                    'ParentDomain' = $InvDom.ParentDomain;
                                    'ChildDomains' = $InvDom.ChildDomains;
                                    'DomainMode' = $InvDom.DomainMode;
                                    'ComputersContainer' = $InvDom.ComputersContainer;
                                    'UsersContainer' = $InvDom.UsersContainer;
                                    'DCCount' = ($($args[1]) | Where-Object {$_.Name -eq $InvDom.DNSRoot}).DomainControllers.Count;
                                    'SysVolContent' = $SysVolDom;
                                    'Users' = $att | Group-Object;
                                    'Computers' = $Comps;
                                    'AdminGroups'=$GrpAll | Where-Object {$_.Keys -in ('Domain Admins','Schema Admins','Enterprise Admins','Server Operators','Account Operators','Administrators','Backup Operators','Print Operators','Domain Controllers','Read-only Domain Controllers','Group Policy Creator Owners','Cryptographic Operators','Distributed COM Users')};
                                    'Groups'=$GrpAll | Sort-Object Values,Keys -desc | Select-Object -First 10;
                                    'SmallGroups' = ($GrpAll | Sort-Object Values | Group-Object Values | Select-Object -Index 0,1 | Measure-Object -Property Count -Sum).Sum
                                }

                            $DomainTable | Export-Clixml -Path ('C:\ADxRay\Hammer\Domain_'+$($args[0]).Name+'.xml')
                        } -ArgumentList $Domain,$Forest.domains,$InvDom,$SysVolDom,$Usrs,$Comps,$GrpAll,$GPOALL
                    }
            }

        function DCjob 
            {

                Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting to Process Domain Controllers Inventory")

                Foreach ($DC in $Global:DCs)
                    {

                        $Inv1 = Receive-Job -Name ('Inv_'+$DC.Name) -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                        Start-job -Name ('Job_'+$DC.Name) -ScriptBlock {
                            if ((test-path ("C:\ADxRay\Hammer\Inv_"+$($args[0]).Name+".xml")) -eq $true) {remove-item -Path ("C:\ADxRay\Hammer\Inv_"+$($args[0]).Name+".xml") -Force}

                            $Inv1 = $($args[1])

                            $TotalMem = if([string]::IsNullOrEmpty($Inv1.Hardware.'Total Physical Memory')){$Inv1.HardwareBkp.'Total Physical Memory'}Else{$Inv1.Hardware.'Total Physical Memory'}
                            $BootTime = if([string]::IsNullOrEmpty($Inv1.Hardware.'System Boot Time')){$Inv1.HardwareBkp.'System Boot Time'}Else{$Inv1.Hardware.'System Boot Time'}
                            $InstallDate = if([string]::IsNullOrEmpty($Inv1.Hardware.'Original Install Date')){$Inv1.HardwareBkp.'Original Install Date'}Else{$Inv1.Hardware.'Original Install Date'}
                            $BiosVer = if([string]::IsNullOrEmpty($Inv1.Hardware.'BIOS Version')){$Inv1.HardwareBkp.'BIOS Version'}Else{$Inv1.Hardware.'BIOS Version'}

                            $DomControl = @{
                                    'Domain' = $Inv1.Inventory.Domain;
                                    'Hostname' = $Inv1.Inventory.Hostname;
                                    'IsReadOnly' = $Inv1.Inventory.IsReadOnly;
                                    'IPv4Address' = $Inv1.Inventory.IPv4Address;
                                    'IsGlobalCatalog' = $Inv1.Inventory.IsGlobalCatalog;
                                    'OperatingSystem' = $Inv1.Inventory.OperatingSystem;
                                    'OperatingSystemVersion' = $Inv1.Inventory.OperatingSystemVersion;
                                    'OperationMasterRoles' = $Inv1.Inventory.OperationMasterRoles;
                                    'Site' = $Inv1.Inventory.Site;
                                    'Backup' = $Inv1.Backup;
                                    'HW_Mem' = $TotalMem;
                                    'HW_Boot' = $BootTime;
                                    'HW_Install' = $InstallDate;
                                    'HW_BIOS' = $BiosVer;
                                    'HotFix' = $Inv1.HotFix;
                                    'NTPStatus' = $Inv1.NTP_Status;
                                    'NTPConf' =  $Inv1.NTP_Config;
                                    'HW_LogicalProc' = $Inv1.Processor;
                                    'HW_FreeSpace' = $Inv1.FreeSpace;
                                    'Spooler_State' = $Inv1.Spooler.State;
                                    'Spooler_StartMode' = $Inv1.Spooler.StartMode;
                                    'DNS' = $Inv1.DNS;
                                    'ldapRR' = $Inv1.ldapRR;
                                    'DCDiag' = $($args[2]) | Select-String -Pattern ($($args[0]).Name.Split('.')[0]);
                                    'InstalledFeatures' = $Inv1.Installed_Features;
                                    'InstalledSoftwaresx64' = $Inv1.Software_64 | Where-Object {$_.DisplayName} | Select-Object DisplayName, DisplayVersion, Publisher;
                                    'InstalledSoftwaresx86' = $Inv1.Software_86 | Where-Object {$_.DisplayName} | Select-Object DisplayName, DisplayVersion, Publisher
                                }

                            $DomControl | Export-Clixml -Path ('C:\ADxRay\Hammer\Inv_'+$($args[0]).Name+'.xml')
                        } -ArgumentList $DC,$Inv1,$Diag
                    }
            }

        function WaitJobs2
            {

                $c = 0
                $WaitTime = get-date
                $WaitTime2 = get-date
                while (get-job | Where-Object {$_.State -eq 'Running'})
                    {
                        $jb = get-job
                        $c = (((($jb.count - ($jb | Where-Object {$_.State -eq 'Running'}).Count)) / $jb.Count) * 100)
                        $c = [math]::Round($c)
                        Write-Progress -activity 'Processing Inventories' -Status "$c% Complete." -PercentComplete $c -CurrentOperation 'Waiting Processing Jobs..'
                        if ((New-TimeSpan -Start $WaitTime2 -End (get-date)).TotalMinutes -ge 10)
                            {
                                Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Warn - Still Waiting for the following Processing Jobs:")
                                foreach($jbb in ($jb | Where-Object {$_.State -eq 'Running'}))
                                    {
                                        Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Warn - Job: "+$jbb.Name)
                                    }
                                $WaitTime2 = get-date
                            }
                        if ((New-TimeSpan -Start $WaitTime -End (get-date)).TotalMinutes -ge $JobTimeout)
                            {
                                Get-Job | Stop-Job | Out-Null
                                Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Err - Timing Out Inventory Jobs")
                            }
                        Start-Sleep -Seconds 2
                    }
                Write-Progress -activity 'Running Inventories' -Status "100% Complete." -Completed

                Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - All Inventories are completed")
            
            }


    if($Global:Option -eq 1)
        {
            HammerForest
            HammerDomain
            HammerDC
        }
    elseif($Global:Option -eq 2)
        {
            HammerForest
        }
    elseif($Global:Option -eq 3)
        {
            HammerForest
            HammerDomain
        }
    
    WaitJobs

    if($Global:Option -eq 1)
        {
            ForestJob
            DomainJob
            DCjob
        }
    elseif($Global:Option -eq 2)
        {
            ForestJob
        }
    elseif($Global:Option -eq 3)
        {
            ForestJob
            DomainJob
        }

    WaitJobs2

    $jbs = Get-Job

    foreach ($JB in $jbs){
    $JbName = $jb.Name 
    $jbcmd = $jb.command
    if ($JB.State -eq 'Failed') 
    {
    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - The following Inventory Job Failed: "+$jbName)
    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - With the following Command Line: "+$jbcmd)
    }
    $time = New-TimeSpan -Start $JB.PSBeginTime -End $JB.PSEndTime
    $TimeJobMin = $time.TotalMinutes.ToString('#######.##')
    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - The following Inventory Job: "+$jbName+'. run time was: '+$TimeJobMin+' Minutes.')
    }

    Write-Host ('End of Hammer phase. ') -NoNewline
    write-host ($jbs | Where-Object {$_.State -eq 'Completed'}).Count -NoNewline -ForegroundColor Magenta
    Write-Host ' Inventory jobs completed and ' -NoNewline
    write-host ($jbs | Where-Object {$_.State -eq 'Failed'}).Count -NoNewline -ForegroundColor Red
    Write-Host ' Inventory jobs failed..'

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - End of Hammer")

    Get-Job | Remove-Job

}

######################################### END OF HAMMER ############################################




######################################### BEGIN OF REPORTING ############################################



function Report {

Add-Content $report "<html>" 
Add-Content $report "<head>" 
Add-Content $report "<meta http-equiv='Content-Type' content='text/html; charset=iso-8859-1'>" 
Add-Content $report "<title>ADxRay - $Forest</title>"
add-content $report '<STYLE TYPE="text/css">' 
add-content $report  "<!--" 
add-content $report  "body {" 
add-content $report  "font: normal 8pt/16pt Verdana;"
add-content $report  "color: #000000;"
add-content $report  "margin-left: 50px;" 
add-content $report  "margin-top: 80px;" 
add-content $report  "margin-right: 50px;" 
add-content $report  "margin-bottom: 10px;" 
add-content $report  "}" 
add-content $report  "p {font: 8pt/16pt Verdana;}"
add-content $report  "h1 {font: 20pt Verdana;margin-bottom: 0px;}"
add-content $report  "h2 {font: 15pt Verdana;margin-bottom: 0px;}"
add-content $report  "h3 {font: 13pt Verdana;margin-bottom: 0px;}"
add-content $report  "td {font: normal 8pt Verdana;}"
add-content $report  "th {font: bold 8pt Verdana;}"
add-content $report  "a {color: blue;}"

add-content $report ".tablink {"
add-content $report "background-color: #555;"
add-content $report "color: white;"
add-content $report "float: left;"
add-content $report "border: none;"
add-content $report "outline: none;"
add-content $report "cursor: pointer;"
add-content $report "padding: 14px 16px;"
add-content $report "font-size: 17px;"
add-content $report "width: 20%;"
add-content $report "}"
add-content $report ".tablink:hover {"
add-content $report "background-color: #777;"
add-content $report "}"
add-content $report ".tabcontent {"
add-content $report "color: black;"
add-content $report "display: none;"
add-content $report "padding: 100px 20px;"
add-content $report "height: 100%;"
add-content $report "}"

add-content $report  "</style>" 
Add-Content $report "</head>" 
Add-Content $report "<body LINK='Black' VLINK='Black'>" 

######################################### HEADER #############################################

add-content $report "<BR>"
add-content $report  "<table width='100%' bgcolor='Black'>" 
add-content $report  "<tr>" 
add-content $report  "<td colspan='7' height='130' align='center' bgcolor='Black'>" 
add-content $report  "<font face='tahoma' color='#0000FF' size='75'><strong><a href='https://github.com/Merola132/ADxRay'>Active Directory xRay Report</a></strong></font>" 
add-content $report  "</td>"  
add-content $report  "</tr>"
add-content $report  "</table>"

$button = @'
<button class="tablink" onclick="openTab('Forest')" id="OpenFirst">Forest</button>
'@
add-content $report $button
$button = @'
<button class="tablink" onclick="openTab('Domains')">Domains</button>
'@
add-content $report $button
$button = @'
<button class="tablink" onclick="openTab('DomainControllers')">Domain Controllers</button>
'@
add-content $report $button
$button = @'
<button class="tablink" onclick="openTab('Security')">Security</button>
'@
add-content $report $button
$button = @'
<button class="tablink" onclick="openTab('Inventory')">Hardware / Software</button>
'@
add-content $report $button

Add-Content $report "<table><tr><td><font face='tahoma' color='#000000' size='2'><strong>Version: $Ver</font></td></tr></table>"
add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td><font face='verdana' size='1'>This Report is intended to help network administrators and contractors to get a better understanding and overview of the actual status and health of theirs Active Directory Forest, Domains, Domain Controllers, DNS Servers and Active Directory objects such as User Accounts, Computer Accounts, Groups and Group Policies. This report has been tested in several Active Directory topologies and environments without further problems or impacts in the servers or environment´s performance. If you however experience some sort of problem while running this script/report. Feel free to send that feedback and I will help to investigate as soon as possible (feedback information’s are presented at the end of this report). Thanks for using.</font></td></tr></TABLE>"



######################################### FOREST HEADER #############################################

add-content $report "<div id='Forest' class='tabcontent'>"

add-content $report  "<table width='100%' border='0'>" 
add-content $report  "<tr bgcolor='White'>" 
add-content $report  "<td colspan='7' height='70' align='center'>" 
add-content $report  "<font face='verdana' color='#000000' size='62'>Active Directory Forest<HR></font>" 
add-content $report  "</td>" 
add-content $report  "</tr>" 
add-content $report  "</table>" 

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>This section is intended to give an overall view of the <B>Active Directory Forest</B>, as so as the <B>Active Directory Domains</B> and <B>Domain Controllers</B> and configured <B>Trusts</B> between Active Directory Domains and others Active Directory Forests.</td></tr></TABLE>" 

add-content $report "<BR><BR><BR>"

######################################### FOREST #############################################

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting Forest Report: "+$Forest)

write-host 'Starting Forest Analysis..'

try{

add-content $report  "<CENTER>"
add-content $report  "<h3>Active Directory Forest View ($Forest)</h3>" 
add-content $report  "</CENTER>"
add-content $report "<BR>"

add-content $report  "<table width='40%' align='center' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 

Add-Content $report "</tr>" 

$Fore = Import-Clixml -Path C:\ADxRay\Hammer\Forest.xml

$ForeName = $Forest.Name
$Dom = $Fore.Domains
$RecycleBin = $Fore.RecycleBin
$ForeMode = $Fore.ForestMode.Value
$ForeGC = $Fore.GlobalCatalogs
$ForeSites = $Fore.Sites
$SPN = $Fore.SPN

$dupdnsfor = 0
$dupdnsdom = 0
Foreach ($dup in $Fore.DuplicatedDNSZones){
if ($dup -like '*DC=ForestDnsZones,*') {$dupdnsfor ++}
if ($dup -like '*DC=DomainDnsZones,*') {$dupdnsdom ++}
}

Add-Content $report "<tr>" 
Add-Content $report  "<th bgcolor='WhiteSmoke' font='tahoma'><B>Forest Name</B></th>" 
Add-Content $report "<td bgcolor='White' align=center>$ForeName</td>" 
Add-Content $report "</tr>" 
Add-Content $report "<tr>" 
Add-Content $report  "<th bgcolor='WhiteSmoke' font='tahoma'><B>Domains</B></th>" 
Add-Content $report "<td bgcolor='White' align=center>$Dom</td>" 
Add-Content $report "</tr>" 
Add-Content $report "<tr>" 
Add-Content $report  "<th bgcolor='WhiteSmoke' font='tahoma'><B>Forest Functional Level</B></th>" 
    if ($ForeMode -like '*NT*' -or $ForeMode -like '*2000*' -or $ForeMode -like '*2003*')
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$ForeMode</font></td>" 
        }
    elseif ($ForeMode -like '*2008*') 
        {
            Add-Content $report "<td bgcolor= 'Yellow' align=center>$ForeMode</td>" 
        }
    elseif ($ForeMode -like '*2019*' -or $ForeMode -like '*2016*' -or $ForeMode -like '*2012*') 
        {      
            Add-Content $report "<td bgcolor= 'Lime' align=center>$ForeMode</td>" 
        }
    else
        {
            Add-Content $report "<td bgcolor='White' align=center>$ForeMode</td>" 
        }
Add-Content $report "</tr>" 
Add-Content $report "<tr>" 
Add-Content $report  "<th bgcolor='WhiteSmoke' font='tahoma'><B>Global Catalogs</B></th>" 
Add-Content $report "<td bgcolor='White' align=center>$ForeGC</td>" 
Add-Content $report "</tr>" 
Add-Content $report "<tr>" 
Add-Content $report  "<th bgcolor='WhiteSmoke' font='tahoma'><B>Recycle Bin Enabled</B></th>" 
    if ($RecycleBin -ne 'Enabled')
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$RecycleBin</font></td>" 
        }
    else
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>$RecycleBin</td>" 
        }
Add-Content $report "</tr>" 
Add-Content $report "<tr>" 
Add-Content $report  "<th bgcolor='WhiteSmoke' font='tahoma'><B>Sites</B></th>" 
Add-Content $report "<td bgcolor='White' align=center>$ForeSites</td>" 

Add-Content $report "</tr>" 

Add-Content $report "<tr>" 
Add-Content $report  "<th bgcolor='WhiteSmoke' font='tahoma'><B>Duplicate SPN</B></th>" 
    if ($SPN -ne 'found 0 group of duplicate SPNs.')
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$SPN</font></td>" 
        }
    else
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>$SPN</td>" 
        }
Add-Content $report "</tr>" 
Add-Content $report "<tr>" 
Add-Content $report  "<th bgcolor='WhiteSmoke' font='tahoma'><B>Duplicated DNS Zones in Forest level</B></th>" 
    if ($dupdnsfor -ge 1)
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$dupdnsfor</font></td>" 
        }
    else
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>$dupdnsfor</td>" 
        }
Add-Content $report "</tr>" 
Add-Content $report "<tr>" 
Add-Content $report  "<th bgcolor='WhiteSmoke' font='tahoma'><B>Duplicated DNS Zones in Domain level</B></th>" 
    if ($dupdnsdom -ge 1)
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$dupdnsdom</font></td>" 
        }
    else
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>$dupdnsdom</td>" 
        }
Add-Content $report "</tr>" 



Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - RecycleBin status: "+$RecycleBin)

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - End of Forest Reporting phase.")


}
Catch { 
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors found -------------")
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Err - The following error ocurred during catcher: "+$_.Exception.Message)
}

Add-content $report  "</table>"


add-content $report "<BR><BR><BR>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Be sure to investigate and solve any issues reported here, also is important to remember to enable every feature available. Those features were developed by the Microsoft team to help you troubleshoot and manage the environment.</td></tr></TABLE>" 

add-content $report "<BR><BR><BR><BR>"





######################################### TRUST #############################################

write-host 'Starting Trust Analysis..'

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting Trust reporting")

$Trust = $Fore.Trusts

if ($Trust) { 

try{

add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>Active Directory Trusts View ($Forest)</h3>" 
add-content $report  "</CENTER>"
add-content $report "<BR>"


add-content $report  "<table width='80%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='10%' align='center'><B>Source</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Trusted Domain</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>Type</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>ForestTransitive</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>IntraForest</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>SID Filtering</B></td>"


Add-Content $report "</tr>" 

Foreach ($Trusts in $Trust)
    {
        Add-Content $report "<tr>" 

        $T3Source = $Trusts.Source
        $T3Target = $Trusts.Target
        $T3Dir = $Trusts.Direction
        $T3Trans = $Trusts.ForestTransitive
        $T3Intra = $Trusts.IntraForest
        $T3SIDFil = $Trusts.SIDFilteringForestAware

        Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Trust Found for: "+$T3Source+ " To "+$T3Target)
    
        Add-Content $report "<td bgcolor='White' align=center>$T3Source</td>" 
        Add-Content $report "<td bgcolor='White' align=center>$T3Target</td>" 
        Add-Content $report "<td bgcolor='White' align=center>$T3Dir</td>" 
        Add-Content $report "<td bgcolor='White' align=center>$T3Trans</B></td>" 
        Add-Content $report "<td bgcolor='White' align=center>$T3Intra</td>" 
        Add-Content $report "<td bgcolor='White' align=center>$T3SIDFil</td>" 

        Add-Content $report "</tr>" 
    }

}
Catch { 
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors found -------------")
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Err - The following error ocurred during catcher: "+$_.Exception.Message)
}
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - End of TRUST Report phase.")

Add-content $report  "</table>"

add-content $report "</CENTER>"


add-content $report "<BR><BR><BR>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Investigate the existing Trusts between domains and specially between forests. And analyze if there is a real need for its existence.</td></tr></TABLE>" 

add-content $report "<BR><BR><BR><BR>"


}



add-content $report "<BR><BR><BR><BR><BR><BR>"
add-content $report "<BR><A HREF='#top'>Back to the top</A><BR>"
add-content $report "<BR><TABLE BORDER='1' CELLPADDING='5'><TR><TD BGCOLOR='Silver'><A NAME='Disclaimer'><B>Disclaimer:</B></A> This report was generated using the ADxRay Powershell Script. The information provided in this report is provided 'as-is' and is intended for information purposes only. The information present at the script is licensed 'as-is'. You bear the risk of using it. The contributors give no express warranties, guarantees or conditions. You may have additional consumer rights under your local laws which this license cannot change. To the extent permitted under your local laws, the contributors exclude the implied warranties of merchantability, fitness for a particular purpose and non-infringement. Any feedback or improvements feel free to email me at: <a href='mailto:merola@outlook.com?Subject=ADxRay%20feedback' target='_top'>Claudio Merola</a></TD></TR></TABLE>"
add-content $report "<BR><TABLE BORDER='1' CELLPADDING='5'><TR><TD BGCOLOR='Silver'><A NAME='More'><B>More:</B></A> If you wish to have a better inventory and reporting regarding your Active Directory environment, Get in touch with your Microsoft representative to run an On-Demand Assessment in your Active Directory environment. On-Demand Assessment will give you a deeper view and understanding of every single issue existing in the environment. More details at: <a href='https://docs.microsoft.com/en-us/services-hub/health/'>Services Hub On-Demand Assessments</a></TD></TR></TABLE>"

add-content $report "<BR><BR><BR><BR>"

add-content $report "</div>"



######################################### DOMAINS HEADER #############################################

add-content $report "<div id='Domains' class='tabcontent'>"

add-content $report  "<table width='100%' border='0'>" 
add-content $report  "<tr bgcolor='White'>" 
add-content $report  "<td colspan='7' height='70' align='center'>" 
add-content $report  "<font face='verdana' color='#000000' size='62'>Active Directory Domains<HR></font>" 
add-content $report  "</td>" 
add-content $report  "</tr>" 
add-content $report  "</table>" 

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>This section is intended to give an overall view of the existing <B>Active Directory Domains</B>, as so as the <B>Active Directory Objects</B>, <B>Active Directory Group Policy Objects</B> and <B>Active Directory SysVol’s Content</B>. </td></tr></TABLE>" 

add-content $report "<BR><BR><BR>"


######################################### DOMAIN #############################################

write-host 'Running Domains Reporting..'

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting Domains Reporting")


add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>Active Directory Domains View ($Forest)</h3>" 
add-content $report  "</CENTER>"
add-content $report "<BR>"

Try{

Add-Content $report "</tr>" 

Foreach ($Domain0 in $Global:DomainNames)
    {

    $Domain1 = Import-Clixml -Path ('C:\ADxRay\Hammer\Domain_'+$Domain0+'.xml')

    Add-Content $report "<tr>" 
    
    $D2Name = $Domain1.DNSRoot
    $D2Parent = $Domain1.ParentDomain
    $D2Child = $Domain1.ChildDomains
    $D2Mode = $Domain1.DomainMode
    $D2CompCont = $Domain1.ComputersContainer
    $D2UserCont = $Domain1.UsersContainer
    $D2Count = $Domain1.DCCount 

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Reporting the following domain: "+$D2Name)

add-content $report  "<table width='40%' align='center' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 

Add-Content $report "</tr>" 

Add-Content $report "<tr>" 
Add-Content $report  "<th bgcolor='WhiteSmoke' font='tahoma'><B>Topology</B></th>" 

    if ($Domain1.Children.Count -eq '' -and $Domain1.Parent.Count -eq '')
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Single-Domain</td>"
        }
    elseif ($Domain1.Count -ge 2 -and $Domain1.Children.Count -ge 2 -and $Trust1.ForestTransitive.Count -eq '') 
        { 
            Add-Content $report "<td bgcolor= 'Lime' align=center>Multi-Domain</td>" 
        }
    elseif ($Domain1.Count -ge 2 -and $Domain1.Children.Count -ge 2 -and $Trust1.ForestTransitive.Count -ne '') 
        { 
            Add-Content $report "<td bgcolor= 'Lime' align=center>Multi-Forest</td>" 
        }
Add-Content $report "</tr>" 

    
Add-Content $report "<tr>" 
Add-Content $report  "<th bgcolor='WhiteSmoke' font='tahoma'><B>Forest Name</B></th>" 
    Add-Content $report "<td bgcolor='White' align=center>$ForeName</td>" 
Add-Content $report "</tr>"     
Add-Content $report "<tr>" 
Add-Content $report  "<th bgcolor='WhiteSmoke' font='tahoma'><B>Domain Name</B></th>" 
    Add-Content $report "<td bgcolor='White' align=center>$D2Name</td>" 
Add-Content $report "</tr>"     
Add-Content $report "<tr>" 
Add-Content $report  "<th bgcolor='WhiteSmoke' font='tahoma'><B>Number of Domain Controllers</B></th>" 
    Add-Content $report "<td bgcolor='White' align=center>$D2Count</td>" 
Add-Content $report "</tr>"     
Add-Content $report "<tr>" 
Add-Content $report  "<th bgcolor='WhiteSmoke' font='tahoma'><B>Parent Domain</B></th>" 
    Add-Content $report "<td bgcolor='White' align=center>$D2Parent</td>" 
Add-Content $report "</tr>"     
Add-Content $report "<tr>" 
Add-Content $report  "<th bgcolor='WhiteSmoke' font='tahoma'><B>Child Domain</B></th>" 
    Add-Content $report "<td bgcolor='White' align=center>$D2Child</B></td>" 
Add-Content $report "</tr>"     
Add-Content $report "<tr>" 
Add-Content $report  "<th bgcolor='WhiteSmoke' font='tahoma'><B>Domain Functional Level</B></th>" 
    if ($D2Mode -like '*NT*' -or $D2Mode -like '*2000*' -or $D2Mode -like '*2003*')
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$D2Mode</font></td>" 
        }
    elseif ($D2Mode -like '*2008*' -and $D2Mode -notlike '*2008R2*') 
        { 
            Add-Content $report "<td bgcolor= 'Yellow' align=center>$D2Mode</td>" 
        }
    elseif ($D2Mode -like '*2012*' -or $D2Mode -like '*2016*') 
        { 
            Add-Content $report "<td bgcolor= 'Lime' align=center>$D2Mode</td>" 
        }
    else
        {
            Add-Content $report "<td bgcolor='White' align=center>$D2Mode</td>" 
        }
    Add-Content $report "</tr>"     
    Add-Content $report "<tr>" 
    Add-Content $report  "<th bgcolor='WhiteSmoke' font='tahoma'><B>Default Computer Container</B></th>" 
    Add-Content $report "<td bgcolor='White' align=center>$D2CompCont</td>" 
    Add-Content $report "</tr>"     
    Add-Content $report "<tr>" 
    Add-Content $report  "<th bgcolor='WhiteSmoke' font='tahoma'><B>Default User Container</B></th>" 
    Add-Content $report "<td bgcolor='White' align=center>$D2UserCont</td>" 
    Add-Content $report "</tr>" 

    }

}
Catch { 
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors found -------------")
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Err - The following error ocurred during domain reporting: "+$_.Exception.Message)
}
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - End of Domain phase.")

Add-content $report  "</table>"

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Domain's design must be as clear as possible and always based on best practices. Remember to consult <a href='https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/creating-a-site-design'>Creating a Site Design</a> and <a href='https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/determining-the-number-of-domains-required'>Determining the Number of Domains Required</a> before adding any new Domains in the topology.</td></tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR><BR><BR><BR><BR><BR>"


######################################### SYSVOL #############################################

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting SysVol Reporting")

add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>Sysvol Folder Status</h3>" 
add-content $report  "</CENTER>"
add-content $report "<BR>"

add-content $report  "<table width='80%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Extension</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>File Count</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Size (MB)</B></td>" 


Add-Content $report "</tr>" 

Foreach ($Domain in $Global:DomainNames) 
    {

$Domain2 = Import-Clixml -Path ('C:\ADxRay\Hammer\Domain_'+$Domain+'.xml')

$SYSVOL = $Domain2.SysVolContent

Foreach ($Sys in $SYSVOL)
{
$EXTDOM = $Domain
$SYSEXT = $sys.Extension
$SYSCOUNT = $sys.Count
$SYSSIZE = $sys.'TotalSize (MB)'

                if ($SYSSIZE -ge 0.01)
                {

                Add-Content $report "<tr>"

                Add-Content $report "<td bgcolor= 'White' align=center>$EXTDOM</td>"

                if ($SYSEXT -notin ('.bat','.exe','.nix','.vbs','.pol','.reg','.xml','.admx','.adml','.inf','.ini','.adm','.kix','.msi','.ps1','.cmd','.ico'))
                    {
                        Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$SYSEXT</font></td>" 
                    }
                else  
                    {
                        Add-Content $report "<td bgcolor= 'White' align=center>$SYSEXT</td>"
                    }
                Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - "+$SYSEXT+" extension found, total of: "+$SYSCOUNT+" files ("+$SYSSIZE+")")
                Add-Content $report "<td bgcolor='White' align=center>$SYSCOUNT</td>" 

                if ($sys.Totalsize -ge 839436544)
                    {
                        Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$SYSSIZE</font></td>" 
                    }
                else  
                    { 
                        Add-Content $report "<td bgcolor= 'White' align=center>$SYSSIZE</td>"
                    }

                Add-Content $report "</tr>" 
                }
            }
    }

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - End of SYSVol Reporting")

Add-content $report  "</table>"

add-content $report "</CENTER>"

add-content $report "<BR><BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Sysvol folder contain the Group Policies physical files and scripts used in the Group Policy Objects, those folders are replicated between Domain Controllers from time to time, is very important to only keep essential files in Sysvol as so as to keep the folder's size at the very minimum.</td></tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR><BR><BR><BR><BR><BR>"


######################################### USERS #############################################

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting User Accounts Reporting")

add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>User Accounts</h3>" 
add-content $report  "</CENTER>"
add-content $report "<BR>"

add-content $report  "<table width='80%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='15%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Total Users</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Enabled Users</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Disabled Users</B></td>"
Add-Content $report  "<td width='10%' align='center'><B>Reversible Encryption</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Password Not Required</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Password Never Expires</B></td>"
Add-Content $report  "<td width='10%' align='center'><B>Use Kerberos DES</B></td>" 

Add-Content $report "</tr>" 

Foreach ($Domain in $Global:DomainNames)
    {
        Try{
        $UsDomain = $Domain

        $Usrs = Import-Clixml -Path ('C:\ADxRay\Hammer\Domain_'+$Domain+'.xml')

        $AllUsers = ($Usrs.Users | Where-Object {$_.Name -eq 9}).Count
        $UsersDisabled = ($Usrs.Users | Where-Object {$_.Name -eq 1}).Count
        $UsersEnabled = (($Usrs.Users | Where-Object {$_.Name -eq 9}).Count - ($Usrs.Users | Where-Object {$_.Name -eq 1}).Count)
        $UsersDES = ($Usrs.Users | Where-Object {$_.Name -eq 21}).Count
        $UsersReversePWD = ($Usrs.Users | Where-Object {$_.Name -eq 7}).Count
        $UsersPWDNotReq = ($Usrs.Users | Where-Object {$_.Name -eq 5}).Count
        $UsersPWDNeverExpire = ($Usrs.Users | Where-Object {$_.Name -eq 16}).Count


        Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Inventoring User Accounts in the Domain: "+$UsDomain)
        Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Total users found: "+$AllUsers)

        Add-Content $report "<tr>" 

        Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
        Add-Content $report "<td bgcolor='White' align=center>$AllUsers</td>"         
        Add-Content $report "<td bgcolor='White' align=center>$UsersEnabled</td>"               
        Add-Content $report "<td bgcolor='White' align=center>$UsersDisabled</td>"    
        if ($UsersReversePWD -eq 0) 
            {
                Add-Content $report "<td bgcolor= 'Lime' align=center>0</td>"
            }
        else 
            { 
                Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$UsersReversePWD</font></td>" 
            }
        if ($UsersPWDNotReq -eq 0) 
            {
                Add-Content $report "<td bgcolor= 'Lime' align=center>0</td>"
            }
        else 
            { 
                Add-Content $report "<td bgcolor= 'Yellow' align=center>$UsersPWDNotReq</td>" 
            }
        if ($UsersPWDNeverExpire -eq 0) 
            {
                Add-Content $report "<td bgcolor= 'Lime' align=center>0</td>"
            }
        else 
            { 
                Add-Content $report "<td bgcolor= 'Yellow' align=center>$UsersPWDNeverExpire</td>" 
            }
        if ($UsersDES -eq 0) 
            {
                Add-Content $report "<td bgcolor= 'Lime' align=center>0</td>"
            }
        else 
            { 
                Add-Content $report "<td bgcolor= 'Yellow' align=center>$UsersDES</td>" 
            }

    Add-Content $report "</tr>"
    }
Catch { 
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors were found  -------------")
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Err - The following error ocurred during user accounts reporting: "+$_.Exception.Message)
}
    }


Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - User Accounts Reporting finished")

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - End of User Account phase.")

Add-content $report  "</table>" 

add-content $report "<BR><BR>"

add-content $report "<TABLE BORDER=0 WIDTH=95%><tr><td>This overview state of user accounts will present the <B>Total number of users</b>, as so as the total number of <B>Disabled User Accounts</B>, <B>Accounts storing password with Reversible Encryption</B>, <B>Accounts checked with password not required</B>, <B>Accounts using Kerberos DES encryption</B> and User Accounts that have the <B>'Password Never Expires'</B> option set. According to <a href='https://docs.microsoft.com/en-us/azure-advanced-threat-protection/atp-cas-isp-unsecure-account-attributes'>Security assessment: Unsecure account attributes</a> those counters should be <B>0</B> or the smallest as possible. Exceptions may apply, but should not be a common practice.</td></tr></TABLE>" 

add-content $report "</CENTER>"

Write-Host ('User Account Reporting Done. Found: ') -NoNewline
write-host $AllUsers -NoNewline -ForegroundColor Magenta
Write-Host ' User Accounts'

add-content $report "<BR><BR><BR><BR>"



######################################### COMPUTER ACCOUNTS #############################################

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting Computer Accounts reporting")


add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>Computers Accounts</h3>" 
add-content $report  "</CENTER>"
add-content $report "<BR>" 

add-content $report  "<table width='60%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='15%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='8%' align='center'><B>Total Computers</B></td>" 
Add-Content $report  "<td width='8%' align='center'><B>Workstations</B></td>" 
Add-Content $report  "<td width='8%' align='center'><B>Servers</B></td>" 
Add-Content $report  "<td width='15%' align='center'><B>Unsupported Workstations</B></td>" 
Add-Content $report  "<td width='15%' align='center'><B>Unsupported Servers</B></td>" 

Add-Content $report "</tr>" 

Foreach ($Domain in $Global:DomainNames) 
    {

    Try{

    Add-Content $report "<tr>" 

    $PC =  Import-Clixml -Path ('C:\ADxRay\Hammer\Domain_'+$Domain+'.xml')

    $PCAll = $PC.Computers
    $PCAll =[System.Collections.ArrayList]$PCAll
    $PCAll.RemoveAt(0)

    $PCAllC = $PCAll.Count
    $PCServer = ($PCAll | Where-Object {$_ -like '* Server*'}).Count
    $PCWS = ($PCAll | Where-Object {$_ -notlike '* Server*'}).Count
    $PCServerUnsupp = ($PCAll | Where-Object {$_ -like '* Server*'} | Where-Object {$_ -like '* NT*' -or $_ -like '*2000*' -or $_ -like '*2003*' -or $_ -like '*2008*'}).Count
    $PCWSUnsupp = ($PCAll | Where-Object {$_ -notlike '* Server*'} | Where-Object {$_ -like '* NT*' -or $_ -like '*2000*' -or $_ -like '* 95*' -or $_ -like '* 7*' -or $_ -like '* 8 *'  -or $_ -like '* 98*' -or $_ -like '*XP*' -or $_ -like '* Vista*'}).Count


    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Reporting Computer Accounts in the Domain: "+$Domain)
    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Total Computers found: "+$PCAllC)


    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$PCAllC</td>"         
    Add-Content $report "<td bgcolor='White' align=center>$PCWS</td>"
    Add-Content $report "<td bgcolor='White' align=center>$PCServer</td>"           
    if ($PCWSUnsupp -eq '' -or $PCWSUnsupp -eq 0) 
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>0</td>"
        }
    else 
        { 
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$PCWSUnsupp</font></td>" 
        }
    if ($PCServerUnsupp -eq '' -or $PCServerUnsupp -eq 0)  
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>0</td>"
        }
    else 
        { 
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$PCServerUnsupp</font></td>" 
        }
    Add-Content $report "</tr>"
    }
Catch { 
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors were found  -------------")
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Err - The following error ocurred during computer account reporting: "+$_.Exception.Message)
}
    }

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Computer Accounts Reporting finished")

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - End of Computer Account phase.")

Add-content $report  "</table>" 

add-content $report "<BR><BR>"

add-content $report "<TABLE BORDER=0 WIDTH=95%><tr><td>Those counters present a list of total Windows Servers and Workstations, and the total number of Windows Servers and Workstations that are enabled (and possibly active in the environment) but are running unsupported versions of Windows. To verify which versions of Windows are out of support, verify: <a href='https://docs.microsoft.com/en-us/lifecycle/overview/product-end-of-support-overview'>Overview - Product end of support</a>, <a href='https://support.microsoft.com/en-us/help/13853/windows-lifecycle-fact-sheet'>Windows lifecycle fact sheet</a> and <a href='https://support.microsoft.com/en-us/help/10736/windows-what-does-it-mean-if-not-supported'>What does it mean if Windows isn't supported?</a>.</td></tr></TABLE>"  

add-content $report "</CENTER>"

Write-Host ('Computer Account Reporting Done. Found: ') -NoNewline
write-host $PCAllC -NoNewline -ForegroundColor Magenta
Write-Host ' Computer Accounts'

add-content $report "<BR><BR><BR><BR><BR><BR>"


######################################### GROUPS #############################################




add-content $report  "<table width='50%' border='0'>" 
add-content $report  "<tr bgcolor='White'>" 
add-content $report  "<td colspan='7' height='70' align='left'>" 
add-content $report  "<H2>Microsoft's Tiering Model<HR><H2>" 
add-content $report  "</td>" 
add-content $report  "</tr>" 
add-content $report  "</table>"
add-content $report "<TABLE BORDER=0 WIDTH=95%><tr><td>Microsoft recommends the use of Tiering model concept to isolate the maximum as possible the different parts of the environment. This concept is designed to keep each environment as safety as possible by using logon and access restrictions, and even its not perfect or easy to implement in first hand, is by far one of the best approaches to protect an environment against further destruction caused by an eventual attack of Ransonware or invasion. The following image represents the concept:</td></tr></TABLE>"  
add-content $report "<BR>"
add-content $report "<CENTER>"
add-content $report  "<table width='60%' border='0'>" 
add-content $report "<IMG SRC='data:image/gif;base64,/9j/4AAQSkZJRgABAQEAeAB4AAD/4RD0RXhpZgAATU0AKgAAAAgABAE7AAIAAAAOAAAISodpAAQAAAABAAAIWJydAAEAAAAcAAAQ0OocAAcAAAgMAAAAPgAAAAAc6gAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFl1cmkgRGlvZ2VuZXMAAAWQAwACAAAAFAAAEKaQBAACAAAAFAAAELqSkQACAAAAAzg3AACSkgACAAAAAzg3AADqHAAHAAAIDAAACJoAAAAAHOoAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAyMDE1OjEyOjE0IDEyOjQ1OjEyADIwMTU6MTI6MTQgMTI6NDU6MTIAAABZAHUAcgBpACAARABpAG8AZwBlAG4AZQBzAAAA/+ELIGh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8APD94cGFja2V0IGJlZ2luPSfvu78nIGlkPSdXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQnPz4NCjx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iPjxyZGY6UkRGIHhtbG5zOnJkZj0iaHR0cDovL3d3dy53My5vcmcvMTk5OS8wMi8yMi1yZGYtc3ludGF4LW5zIyI+PHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9InV1aWQ6ZmFmNWJkZDUtYmEzZC0xMWRhLWFkMzEtZDMzZDc1MTgyZjFiIiB4bWxuczpkYz0iaHR0cDovL3B1cmwub3JnL2RjL2VsZW1lbnRzLzEuMS8iLz48cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0idXVpZDpmYWY1YmRkNS1iYTNkLTExZGEtYWQzMS1kMzNkNzUxODJmMWIiIHhtbG5zOnhtcD0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wLyI+PHhtcDpDcmVhdGVEYXRlPjIwMTUtMTItMTRUMTI6NDU6MTIuODcyPC94bXA6Q3JlYXRlRGF0ZT48L3JkZjpEZXNjcmlwdGlvbj48cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0idXVpZDpmYWY1YmRkNS1iYTNkLTExZGEtYWQzMS1kMzNkNzUxODJmMWIiIHhtbG5zOmRjPSJodHRwOi8vcHVybC5vcmcvZGMvZWxlbWVudHMvMS4xLyI+PGRjOmNyZWF0b3I+PHJkZjpTZXEgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj48cmRmOmxpPll1cmkgRGlvZ2VuZXM8L3JkZjpsaT48L3JkZjpTZXE+DQoJCQk8L2RjOmNyZWF0b3I+PC9yZGY6RGVzY3JpcHRpb24+PC9yZGY6UkRGPjwveDp4bXBtZXRhPg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8P3hwYWNrZXQgZW5kPSd3Jz8+/9sAQwAHBQUGBQQHBgUGCAcHCAoRCwoJCQoVDxAMERgVGhkYFRgXGx4nIRsdJR0XGCIuIiUoKSssKxogLzMvKjInKisq/9sAQwEHCAgKCQoUCwsUKhwYHCoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioq/8AAEQgBeAMaAwEiAAIRAQMRAf/EAB8AAAEFAQEBAQEBAAAAAAAAAAABAgMEBQYHCAkKC//EALUQAAIBAwMCBAMFBQQEAAABfQECAwAEEQUSITFBBhNRYQcicRQygZGhCCNCscEVUtHwJDNicoIJChYXGBkaJSYnKCkqNDU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6g4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2drh4uPk5ebn6Onq8fLz9PX29/j5+v/EAB8BAAMBAQEBAQEBAQEAAAAAAAABAgMEBQYHCAkKC//EALURAAIBAgQEAwQHBQQEAAECdwABAgMRBAUhMQYSQVEHYXETIjKBCBRCkaGxwQkjM1LwFWJy0QoWJDThJfEXGBkaJicoKSo1Njc4OTpDREVGR0hJSlNUVVZXWFlaY2RlZmdoaWpzdHV2d3h5eoKDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uLj5OXm5+jp6vLz9PX29/j5+v/aAAwDAQACEQMRAD8A+kaKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiikR1kQOjBlYZDA5BFAC0UUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQA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'ALT='Microsoft's Tiering Model'>"
add-content $report  "</table>"
add-content $report "<BR>"
add-content $report "<TABLE BORDER=0 WIDTH=95%><tr><td>If this concept is not already implemented or is not already in full use in your environment, read the following documentation and Microsoft’s official pages regarding the Tiering Models: <a href='https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material'>Active Directory administrative tier model</a>. And implement this model as soon as possible.</td></tr></TABLE>"
add-content $report "<BR><BR>"
add-content $report "</CENTER>"







######################################### TIERING #################################################

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting Groups Reporting")

add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>Active Directory Tier 0 Group Members</h3>" 
add-content $report  "</CENTER>"
add-content $report "<BR>"

add-content $report  "<table width='60%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='15%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='15%' align='center'><B>Group Name</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>Members</B></td>" 

Add-Content $report "</tr>" 

$Groups = @('Domain Admins','Schema Admins','Enterprise Admins','Server Operators','Account Operators','Administrators','Backup Operators','Print Operators','Domain Controllers','Read-only Domain Controllers','Group Policy Creator Owners','Cryptographic Operators','Distributed COM Users')

Foreach ($Domain in $Global:DomainNames) 
    {

    Try{

    $Grp =  Import-Clixml -Path ('C:\ADxRay\Hammer\Domain_'+$Domain+'.xml')

    $Grp = $Grp.AdminGroups

        Foreach ($gp in $Groups)
            {
            $GpTemp = 0
            $GpTemp = $Grp.($gp)
            $CritGrp = 0

            if ($gp -in ('Schema Admins','Domain Controllers','Read-only Domain Controllers','Cryptographic Operators','Distributed COM Users')) {$CritGrp ++}
            $GCounter = $GpTemp

                    $GName = $gp
                    Add-Content $report "<tr>"
                    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
                    Add-Content $report "<td bgcolor='White' align=center>$GName</td>" 

                    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Inventoring Group: "+$GName)
                    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Total members found: "+$GCounter)

                    if ($GCounter -ge 1 -and $CritGrp -ge 1) 
                        {
                            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GCounter</font></td>"
                        }
                    elseif ($GCounter -ge 2 -and $CritGrp -eq 0)  
                        { 
                            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GCounter</font></td>"
                        }
                    else 
                        {
                            Add-Content $report "<td bgcolor='White' align=center>$GCounter</td>" 
                        }     

            Add-Content $report "</tr>"
            } 
            }
            Catch { 
        Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors were found -------------")
        Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Err - The following error ocurred during groups reporting: "+$_.Exception.Message)
                }
    }

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Domain Groups Inventory finished")


Add-content $report  "</table>"

add-content $report "<BR><BR>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Having too many users with more than necessary permissions may result in serious security breaches. Microsoft recommends the group Schema Admins should remain empty until there is a real need to change the environment´s schema, and any member should be removed after that change. Make sure that only the very necessary user accounts are present in those groups, unauthorized users may cause big damage. And remember to review the <a href='https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory'>Best Practices for Securing Active Directory</a>. And specially '<a href='https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models'>Implementing Least-Privilege Administrative Models</a>'. </td></tr></TABLE>" 

add-content $report "</CENTER>"

add-content $report "<BR><BR><BR><BR>"




######################################### GPOs #############################################




add-content $report  "<table width='50%' border='0'>" 
add-content $report  "<tr bgcolor='White'>" 
add-content $report  "<td colspan='7' height='70' align='left'>" 
add-content $report  "<H2>Group Policy Objects<HR><H2>" 
add-content $report  "</td>" 
add-content $report  "</tr>" 
add-content $report  "</table>"
add-content $report "<BR><BR>"
add-content $report "</CENTER>"




######################################### GPOs #############################################

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting Group Policy Objects Reporting")

add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>Group Policy Objects</h3>" 
add-content $report  "</CENTER>"
add-content $report "<BR>"

add-content $report  "<table width='60%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>GPOs</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>Without Link</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>Without Settings</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>Disabled Links</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>Too Many Settings</B></td>" 


Add-Content $report "</tr>" 


Foreach ($Domain in $Global:DomainNames)
    {

    Try{

    [xml]$XmlDocument = Get-Content -Path ('C:\ADxRay\Hammer\GPOs_'+$Domain+'.XML')

    $GPO =  $XmlDocument.report.gpo

    $GPEmpt = ($Gpo | Where-Object {$_.User.VersionDirectory -eq 0 -and $_.User.VersionSysVol -eq 0 -and $_.Computer.VersionDirectory -eq 0 -and $_.Computer.VersionSysVol -eq 0}).Name.Count
    $GPBIG = ($Gpo | Where-Object {(([int]$_.User.VersionDirectory) + ([int]$_.Computer.VersionDirectory)) -ge 1000}).Name.Count
    $GPOAll = $GPO.Count
    $GPOWithouLink = ($GPO  | Where-Object {!$_.LinksTo}).name.Count
    $GPODisables = ($GPO.LinksTo.Enabled | Where-Object {$_ -eq $false}).Count

Add-Content $report "<tr>"

                Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
                Add-Content $report "<td bgcolor='White' align=center>$GPOAll</td>" 

                Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Inventoring Group Policies in the Domain: "+$Domain)
                Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Total GPOs found: "+$GPOAll)
                if ($GPOWithouLink -ge 1) 
                    {
                        Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GPOWithouLink GPOs</font></td>"
                    }
                else 
                    {
                        Add-Content $report "<td bgcolor= 'Lime' align=center>0 GPOs</td>" 
                    }
                if ($GPEmpt -ge 1) 
                    {
                        Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GPEmpt GPOs</font></td>"
                    }
                else 
                    {
                        Add-Content $report "<td bgcolor= 'Lime' align=center>0 GPOs</td>" 
                    }

                if ($GPODisables -ge 1) 
                    {
                        Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GPODisables GPOs</font></td>"
                    }
                else 
                    {
                        Add-Content $report "<td bgcolor= 'Lime' align=center>0 GPOs</td>" 
                    }

                if ($GPBIG -ge 1) 
                    {
                        Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GPBIG GPOs</font></td>"
                    }
                else 
                    {
                        Add-Content $report "<td bgcolor= 'Lime' align=center>0 GPOs</td>" 
                    }

                Add-Content $report "</tr>"
                }
Catch { 
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors were found -------------")
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Err - The following error ocurred during GPO reporting: "+$_.Exception.Message)
}
    }


Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - GPOs Repoorting finished")


Add-content $report  "</table>" 

add-content $report "<BR><BR>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Group Policy represent an important part of Active Directory management (without mention its impact on Servers and Workstation). Make sure GPO conflicts are avoided always as possible, also take GPO backups at a regular basis (<a href='https://docs.microsoft.com/en-us/powershell/module/grouppolicy/backup-gpo?view=win10-ps'>Backup-GPO</a>).</td></tr></TABLE>" 

add-content $report "</CENTER>"

Write-Host ('Found: ') -NoNewline
write-host $GPOall -NoNewline -ForegroundColor Magenta
Write-Host ' GPOs.'
Write-Host 'Running the Reporting Phase..' 

add-content $report "<BR><BR><BR><BR>"


######################################### GPOs WITHOUT LINK #############################################


Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting GPOs Without Link Reporting")


add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>Empty Group Policy Objects</h3>" 
add-content $report  "</CENTER>" 
add-content $report "<BR>"

add-content $report  "<table width='80%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='5%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='15%' align='center'><B>GPOs</B></td>" 
Add-Content $report  "<td width='3%' align='center'><B>User Version</B></td>" 
Add-Content $report  "<td width='3%' align='center'><B>Computer Version</B></td>"
Add-Content $report  "<td width='3%' align='center'><B>Linked</B></td>"  
Add-Content $report  "<td width='5%' align='center'><B>Modification Date</B></td>" 

Add-Content $report "</tr>" 


Foreach ($Domain in $Global:DomainNames) 
    {

    Try{

    [xml]$XmlDocument = Get-Content -Path ('C:\ADxRay\Hammer\GPOs_'+$Domain+'.XML')

    $Gpos = $XmlDocument.report.gpo

    Foreach ($gpo in $gpos)
        {

            $GpoName = $Gpo.Name
            $GpoUserADVer = $Gpo.User.VersionDirectory
            $GpoCompADVer = $Gpo.Computer.VersionDirectory
            $GposNoLink = $GPO | Where-Object {!$_.LinksTo}
            $GpoModDate =  $Gpo.ModifiedTime

            Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Inventoring the Following GPO: "+$GpoName)

            if ($GpoUserADVer -eq 0 -and $GpoCompADVer -eq 0 -and $Gpo.Name -in $GposNoLink.Name)
                { 
                    Add-Content $report "<tr>"
                    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
                    Add-Content $report "<td bgcolor='White' align=center>$GpoName</td>"
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GpoUserADVer</font></td>"
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GpoCompADVer</font></td>"
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>NO</font></td>"
                    Add-Content $report "<td bgcolor='White' align=center>$GpoModDate</td>"
                    Add-Content $report "</tr>"
                }   
            elseif ($GpoUserADVer -eq 0 -and $GpoCompADVer -eq 0)
                { 
                    Add-Content $report "<tr>"
                    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
                    Add-Content $report "<td bgcolor='White' align=center>$GpoName</td>"
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GpoUserADVer</font></td>"
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GpoCompADVer</font></td>"
                    Add-Content $report "<td bgcolor= 'Lime' align=center>YES</td>"
                    Add-Content $report "<td bgcolor='White' align=center>$GpoModDate</td>"
                    Add-Content $report "</tr>"
                }
            elseif ($Gpo.Name -in $GposNoLink.Name)
                { 
                    Add-Content $report "<tr>"
                    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
                    Add-Content $report "<td bgcolor='White' align=center>$GpoName</td>"
                    if ($GpoUserADVer -ge 600)
                        {
                        Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GpoUserADVer</font></td>"
                        }
                    else
                        {
                        Add-Content $report "<td bgcolor= 'White' align=center>$GpoUserADVer</td>"
                        }
                    if ($GpoCompADVer -ge 600)
                        {
                        Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GpoCompADVer</font></td>"
                        }
                    else
                        {
                        Add-Content $report "<td bgcolor= 'White' align=center>$GpoCompADVer</td>"
                        }
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>NO</font></td>"
                    Add-Content $report "<td bgcolor='White' align=center>$GpoModDate</td>"
                    Add-Content $report "</tr>"
                }
        }   
    }
Catch { 
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors were found during the GPO Inventoring -------------")
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Err - The following error ocurred during catcher: "+$_.Exception.Message)
}

}

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - GPOs without link Inventory finished")

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - End of log file")

Add-content $report  "</table>" 

add-content $report "<BR><BR>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Make sure to investigate and solve problems listed above, Having too many unused Group Policies may impact your Active Directory management effort considerable.</td></tr></TABLE>" 

add-content $report "</CENTER>"




add-content $report "<BR><BR><BR><BR><BR><BR>"
add-content $report "<BR><A HREF='#top'>Back to the top</A><BR>"
add-content $report "<BR><TABLE BORDER='1' CELLPADDING='5'><TR><TD BGCOLOR='Silver'><A NAME='Disclaimer'><B>Disclaimer:</B></A> This report was generated using the ADxRay Powershell Script. The information provided in this report is provided 'as-is' and is intended for information purposes only. The information present at the script is licensed 'as-is'. You bear the risk of using it. The contributors give no express warranties, guarantees or conditions. You may have additional consumer rights under your local laws which this license cannot change. To the extent permitted under your local laws, the contributors exclude the implied warranties of merchantability, fitness for a particular purpose and non-infringement. Any feedback or improvements feel free to email me at: <a href='mailto:merola@outlook.com?Subject=ADxRay%20feedback' target='_top'>Claudio Merola</a></TD></TR></TABLE>"
add-content $report "<BR><TABLE BORDER='1' CELLPADDING='5'><TR><TD BGCOLOR='Silver'><A NAME='More'><B>More:</B></A> If you wish to have a better inventory and reporting regarding your Active Directory environment, Get in touch with your Microsoft representative to run an On-Demand Assessment in your Active Directory environment. On-Demand Assessment will give you a deeper view and understanding of every single issue existing in the environment. More details at: <a href='https://docs.microsoft.com/en-us/services-hub/health/'>Services Hub On-Demand Assessments</a></TD></TR></TABLE>"

add-content $report "<BR><BR><BR><BR>"

add-content $report "</div>"





######################################### DOMAIN CONTROLLER HEADER #############################################

add-content $report "<div id='DomainControllers' class='tabcontent'>"

add-content $report  "<table width='100%' border='0'>" 
add-content $report  "<tr bgcolor='White'>" 
add-content $report  "<td colspan='7' height='70' align='center'>" 
add-content $report  "<font face='verdana' color='#000000' size='62'>Domain Controller's Health<HR></font>" 
add-content $report  "</td>" 
add-content $report  "</tr>" 
add-content $report  "</table>" 

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>This section is intended to give an overall view of the <B>Active Directory’s Domain Controllers Health</B>, investigate and solve any problem reported in this section first. As the health of the Domain Controllers are vital for the health of the environment.</td></tr></TABLE>" 

add-content $report "<BR><BR><BR>"


######################################### DC #############################################

write-host 'Running Domain Controller Reporting..'

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting Domain Controllers Reporting")

add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>Active Directory Domain Controllers View ($Forest)</h3>" 
add-content $report  "</CENTER>"
add-content $report "<BR>"

add-content $report  "<table width='90%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='5%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='15%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>Type</B></td>" 
Add-Content $report  "<td width='8%' align='center'><B>IPV4 Address</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>SMB v1</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>Global Catalog</B></td>" 
Add-Content $report  "<td width='15%' align='center'><B>Operating System</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>Build</B></td>"
Add-Content $report  "<td width='10%' align='center'><B>FSMO</B></td>"
Add-Content $report  "<td width='10%' align='center'><B>Site</B></td>"

Add-Content $report "</tr>" 

$svcchannel = 0

foreach ($DC in $Global:DCs)
    {
    Try{
    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Start Reporting of: "+$DC)

    $DCD = Import-Clixml -Path ('C:\ADxRay\Hammer\Inv_'+$DC+'.xml')

    Remove-Variable DCEnabled
    Remove-Variable DCIP
    Remove-Variable SMBv1
    Remove-Variable DCGC
    Remove-Variable DCOS
    Remove-Variable DCOSD
    Remove-Variable FSMO
    Remove-Variable Site

    $Domain = $DCD.Domain
    $DCHostName = $DC
    $DCEnabled = $DCD.IsReadOnly
    $DCIP = $DCD.IPv4Address
    $SMBv1 = $DCD.InstalledFeatures | Where-Object {$_ -contains 'FS-SMB1'}
    $DCGC = $DCD.IsGlobalCatalog
    $DCOS = $DCD.OperatingSystem
    $DCOSD = $DCD.OperatingSystemVersion
    $FSMO = $DCD.OperationMasterRoles
    $Site = $DCD.Site

    Add-Content $report "<tr>"

    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DCHostname</td>" 

    if($DCEnabled -eq 'True')
        {
            Add-Content $report "<td bgcolor='White' align=center>RODC</td>"  
        }
    elseif(($DCEnabled -eq 'False'))
        {
            Add-Content $report "<td bgcolor='White' align=center>Full DC</td>"  
        }
    else
        {
            Add-Content $report "<td bgcolor='White' align=center>$DCEnabled</td>"  
        }

    Add-Content $report "<td bgcolor='White' align=center>$DCIP</td>" 

    if (!$SMBv1)
        {
            Add-Content $report "<td bgcolor='White' align=center>Disable</td>"  
        }
    else
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Enable</font></td>"  
        }

    Add-Content $report "<td bgcolor='White' align=center>$DCGC</td>" 

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Reporting Operating System Version of: "+$DCHostName)
        if ($DCOS -like '* NT*' -or $DCOS -like '* 2000*' -or $DCOS -like '* 2003*' -or $DCOS -like '* 2008*')
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$DCOS</font></td>" 
        }
    elseif ($DCOS -like '* 2012*' -or $DCOS -like '* 2016*') 
        {
            Add-Content $report "<td bgcolor= 'Yellow' align=center>$DCOS</td>" 
        }
    elseif ($DCOS -like '* 2019*' -or $DCOS -like '* 2022*') 
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>$DCOS</td>" 
        }
    else
        {
            Add-Content $report "<td bgcolor='White' align=center>$DCOS</td>" 
        }

        if (($DCOS -eq 'Windows Server Standard' -or $DCOS -eq 'Windows Server Datacenter') -and $DCOSD -notin $SupBuilds)
        {
            $svcchannel ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$DCOSD</font></td>" 
        }
    elseif (($DCOS -eq 'Windows Server Standard' -or $DCOS -eq 'Windows Server Datacenter') -and $DCOSD -in $SupBuilds)
        {
            $svcchannel ++
            Add-Content $report "<td bgcolor= 'Lime' align=center>$DCOSD</td>" 
        }
    else
        {
            Add-Content $report "<td bgcolor='White' align=center>$DCOSD</td>" 
        }


    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Reporting FSMO of: "+$DCHostName)

    Add-Content $report "<td bgcolor='White' align=center>$FSMO</td>" 

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Reporting Site of: "+$DCHostName)

    Add-Content $report "<td bgcolor='White' align=center>$Site</td>" 
    
    Add-Content $report "</tr>" 

    }
    Catch 
            { 
    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors found -------------")
    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Err - The following error ocurred during catcher: "+$_.Exception.Message)    
            }
    }


Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Domain Controllers Reporting finished")

Add-content $report  "</table>" 

add-content $report "</CENTER>"


if ($SvcChannel -ge 1)
{

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Domain Controllers running Semi-Annual Servicing Channel were found in this environment. Since Windows Server 2019, Microsoft made available Semi-Annual Channels for Windows Server Builds <a href='https://docs.microsoft.com/en-us/windows-server/get-started-19/servicing-channels-19'>Windows Server servicing channels: LTSC and SAC</a>. Since this update model has a considerable lower lifecycle, be sure to keep those servers up to date! </td></tr></TABLE>" 

add-content $report  "</CENTER>"

}

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Having too many Domain Controllers in the environment does not represent a problem. But using an oversized topology might increase the administrative effort and impact the security of the environment as every writable Domain Controller have a full copy of every user account along with their password. Make sure to keep a reasonable number of Domain Controllers and keep they as secured as possible. Also remember to only keep supported versions of Windows running in the environment, as unsupported versions may increase the attack surface of Active Directory and put the entire environment at risk. </td></tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR><BR><BR><BR><BR><BR>"




######################################### NTP #############################################

write-host 'NTP Reporting..'

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting NTP Reporting")

add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>Active Directory Domain Controllers NTP Settings ($Forest)</h3>" 
add-content $report  "</CENTER>"
add-content $report "<BR>"

add-content $report  "<table width='90%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='5%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='15%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>FSMO</B></td>" 
Add-Content $report  "<td width='15%' align='center'><B>NTP Source</B></td>" 
Add-Content $report  "<td width='15%' align='center'><B>Last Successful Sync Time</B></td>" 
Add-Content $report  "<td width='15%' align='center'><B>Stratum</B></td>"
Add-Content $report  "<td width='8%' align='center'><B>Type</B></td>" 

Add-Content $report "</tr>" 


foreach ($DC in $Global:DCs)
    {
    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Start NTP Reporting of: "+$DC)

    $DCD = Import-Clixml -Path ('C:\ADxRay\Hammer\Inv_'+$DC+'.xml')

    $Domain = $DCD.Domain
    $DCHostName = $DC
    $DCNTPStatus = $DCD.NTPStatus
    $DCNTPConf = $DCD.NTPConf

    $DCNTPSource = ($DCNTPStatus | Select-String -Pattern 'Source:').ToString().replace('Source: ','');
    $DCNTPLastSync = [string]($DCNTPStatus | Select-String -Pattern 'Last Successful Sync Time:');
    $DCNTPLastSync = [string]$DCNTPLastSync.replace('Last Successful Sync Time:','');
    $DCNTPStratum = ($DCNTPStatus | Select-String -Pattern 'Stratum:').ToString().replace('Stratum: ','');
    $DCNTPType = ($DCNTPConf | Select-String -Pattern 'Type:').ToString().replace('Type: ','');

    Add-Content $report "<tr>"

    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DCHostname</td>" 

    if ($DCD.OperationMasterRoles -like '*PDC*')
        {
            Add-Content $report "<td bgcolor='White' align=center>PDC Emulator</td>"  
        }
    else
        {
            Add-Content $report "<td bgcolor='White' align=center></td>"   
        }

    Add-Content $report "<td bgcolor='White' align=center>$DCNTPSource</td>" 

    Add-Content $report "<td bgcolor='White' align=center>$DCNTPLastSync</td>" 

    Add-Content $report "<td bgcolor='White' align=center>$DCNTPStratum</td>" 

    Add-Content $report "<td bgcolor='White' align=center>$DCNTPType</td>" 
    
    Add-Content $report "</tr>" 

    }


Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - NTP Reporting finished")

Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Active Directory health depends deeply of time synchronization. Keeping the time synchronization working correctly should be a main concern of every system admin. </td></tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR><BR><BR><BR><BR><BR>"



######################################### DNS Server #############################################

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DNS Server Reporting")

add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>DNS Servers</h3>" 
add-content $report  "</CENTER>"
add-content $report "<BR>"

add-content $report  "<table width='80%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='10%' align='center'><B>Server Name</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Server Scavaging Enabled</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Number of Zones</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Zones Scavaging Enabled</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Suspicious Root Hints</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>SRV Records</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Server Recursion Enabled</B></td>"
Add-Content $report  "<td width='10%' align='center'><B>Bind Secondaries Enabled</B></td>" 

Add-Content $report "</tr>" 

        foreach ($DC in $Global:DCs)
            {

                remove-variable ldapRR
                remove-variable DNS

                $DCD = Import-Clixml -Path ('C:\ADxRay\Hammer\Inv_'+$DC+'.xml')

                $DNS = $DCD.DNS

                Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Reporting DNS Server: "+$DC)

                $ldapRR = $DCD.ldapRR
                    
                $DNSSRVRR = 'Ok'
                Foreach ($DCOne in $Global:DCs)
                    {
                        if ($DCOne.split('.')[0] -notin $ldapRR.RecordData.DomainName.split('.')[0])
                            {
                                $DNSSRVRR = 'Missing'
                            }
                    }
                $DNSRootHintC = @()
                Foreach ($dd in $dns.ServerRootHint.NameServer.RecordData) 
                    {
                        if ($dd.NameServer -notlike '*.root-servers.net.')
                            {
                                $DNSRootHintC += $dd.NameServer
                            }
                    }

                $DNSName = $DNS.ServerSetting.ComputerName
                $DNSZoneScavenge = ($dns.ServerZoneAging | Where-Object {$_.AgingEnabled -eq $True }).ToString.Count
                $DNSBindSec = $DNS.ServerSetting.BindSecondaries
                $DNSSca = $DNS.ServerScavenging.ScavengingState
                $DNSRecur = $DNS.ServerRecursion.Enable
                $DNSZoneCount = ($DNS.ServerZone | Where-Object {$_.ZoneName -notlike '*.arpa' -and $_.ZoneName -ne 'TrustAnchors'}).Count
                $DNSRootC = $DNSRootHintC.Count


                Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Validating DNS Server: "+$DNSName)

                Add-Content $report "<tr>"
                Add-Content $report "<td bgcolor='White' align=center>$DNSName</td>" 
                if ($DNSSca -eq $true)
                    {
                        Add-Content $report "<td bgcolor= 'Lime' align=center>$DNSSca</td>"
                    }
                else  
                    { 
                        Add-Content $report "<td bgcolor= 'Yellow' align=center>$DNSSca</td>" 
                    }
                Add-Content $report "<td bgcolor='White' align=center>$DNSZoneCount</td>" 

                Add-Content $report "<td bgcolor='White' align=center>$DNSZoneScavenge</td>" 
                if ($DNSRootC -eq '' -or $DNSRootC -eq 0)
                    {
                        Add-Content $report "<td bgcolor= 'Lime' align=center>0</td>"
                    }
                else  
                    { 
                        Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$DNSRootC</font></td>" 
                    }

                if ($DNSSRVRR -eq 'Missing')
                    {
                        Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$DNSSRVRR</font></td>" 
                    }
                else  
                    {
                        Add-Content $report "<td bgcolor= 'Lime' align=center>$DNSSRVRR</td>"
                    }

                if ($DNSRecur -eq $false)
                    {
                        Add-Content $report "<td bgcolor= 'Lime' align=center>$DNSRecur</td>"
                    }
                else  
                    { 
                        Add-Content $report "<td bgcolor= 'Yellow' align=center>$DNSRecur</td>" 
                    }
                Add-Content $report "<td bgcolor='White' align=center>$DNSBindSec</td>" 


                Add-Content $report "</tr>" 
            
            }


Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - DNS Servers Reporting finished")

Add-content $report  "</table>"

add-content $report "</CENTER>"

add-content $report "<BR><BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>DNS is an important part of Active Directory’s health, so its maintenance is very critical for the safety and functionality of the environment. If you did not disabled DNS Server recursion don't forget to do so according to <a href='https://support.microsoft.com/hr-ba/help/2678371/microsoft-dns-server-vulnerability-to-dns-server-cache-snooping-attack'>'Microsoft DNS Server vulnerability to DNS Server Cache snooping attacks'</a>. Enabling <B>Scavenging</B> is also very important to avoid old records in the DNS. Also verify the <B>forwarders</B> and <B>conditional forwarders</B>.</td></tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR><BR><BR><BR><BR><BR>"



######################################### DCs Health HEADER #############################################

write-host 'Running DCDiag Report Phase..'

add-content $report  "<table width='100%' border='0'>" 
add-content $report  "<tr bgcolor='White'>" 
add-content $report  "<td colspan='7' height='50' align='center'>" 
add-content $report  "<font face='verdana' color='#000000' size='50'>Domain Controller Diagnostic Tool<HR></font>" 
add-content $report  "</td>" 
add-content $report  "</tr>" 
add-content $report  "</table>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>This section will give a detailed view of the Domain Controller's health. With tests and validations based on <B>DCDiag</B> tool and should be enough to give a deep status of Domain Controller’s overall heatlh. </td></tr></TABLE>" 


######################################### DCDiag´s  ###############################################

if ($Global:DCs.Count -ge 50) 
{

add-content $report "<BR><BR><BR>"

add-content $report "<CENTER>"

add-content $report  "<table width='90%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='5%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='15%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='8%' align='center'><B>Connectivity</B></td>"
Add-Content $report  "<td width='8%' align='center'><B>VerifyReferences</B></td>"
Add-Content $report  "<td width='8%' align='center'><B>Advertising</B></td>"
Add-Content $report  "<td width='8%' align='center'><B>FrsEvent</B></td>"
Add-Content $report  "<td width='8%' align='center'><B>DFSREvent</B></td>"
Add-Content $report  "<td width='8%' align='center'><B>SysVolCheck</B></td>"
Add-Content $report  "<td width='8%' align='center'><B>KccEvent</B></td>"
Add-Content $report  "<td width='8%' align='center'><B>KnowsOfRoleHolders</B></td>"
Add-Content $report  "<td width='8%' align='center'><B>MachineAccount</B></td>"
Add-Content $report  "<td width='8%' align='center'><B>NCSecDesc</B></td>"
Add-Content $report  "<td width='8%' align='center'><B>NetLogons</B></td>"
Add-Content $report  "<td width='8%' align='center'><B>ObjectsReplicated</B></td>"
Add-Content $report  "<td width='8%' align='center'><B>Replications</B></td>"
Add-Content $report  "<td width='8%' align='center'><B>RidManager</B></td>"
Add-Content $report  "<td width='8%' align='center'><B>Services</B></td>"
Add-Content $report  "<td width='8%' align='center'><B>SystemLog</B></td>"
Add-Content $report "<tr>"

ForEach ($DC in $Global:DCs)
{    
    $DCHostName = $DC

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag Reporting of: "+$DC.Name)

    $DCD = Import-Clixml -Path ('C:\ADxRay\Hammer\Inv_'+$DC+'.xml')

    $Domain = $DCD.Domain

    $DC = $DC.ToString()
    $DC = $DC.split('.')
    $DC = $DC[0]

    Add-Content $report "<tr>"

    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DCHostname</td>" 

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag initial validation: "+$DC)

if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test Connectivity')).Count -eq $true) 
    {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Passed</td>"
    }
    elseif(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test Connectivity')).Count -eq $true) 
                {
                    Add-Content $report "<td bgcolor='Yellow' align=center>Failed</td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor='Yellow' align=center>Missing</td>"
                }

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag VerifyReference Test: "+$DC)
if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test VerifyReferences')).Count -eq $true) 
    {
    Add-Content $report "<td bgcolor= 'Lime' align=center>Passed</td>"
    }
    elseif(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test VerifyReferences')).Count -eq $true) 
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Failed</font></td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Missing</font></td>"
                }

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag Advertising Test: "+$DC)

if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test Advertising')).Count -eq $true) 
    {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Passed</td>"
    }
    elseif(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test Advertising')).Count -eq $true) 
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Failed</font></td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Missing</font></td>"
                }

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag FrsEvent: "+$DC)

if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test FrsEvent')).Count -eq $true) 
    {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Passed</td>"
    }
    elseif(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test FrsEvent')).Count -eq $true) 
                {
                    Add-Content $report "<td bgcolor='Yellow' align=center>Failed</td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor='Yellow' align=center>Missing</td>"
                }

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag DFSREvent Test: "+$DC)

if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test DFSREvent')).Count -eq $true) 
    {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Passed</td>"
    }
    elseif(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test DFSREvent')).Count -eq $true) 
                {
                    Add-Content $report "<td bgcolor='Yellow' align=center>Failed</td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor='Yellow' align=center>Missing</td>"
                }


Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag SysvolCheck Test: "+$DC)

if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test SysVolCheck')).Count -eq $true) 
    {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Passed</td>"
    }
    elseif(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test SysVolCheck')).Count -eq $true) 
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Failed</font></td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Missing</font></td>"
                }

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag KccEvent Test: "+$DC)

if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test KccEvent')).Count -eq $true) 
    {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Passed</td>"
    }
    elseif(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test KccEvent')).Count -eq $true) 
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Failed</font></td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Missing</font></td>"
                }

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag KnowsOfRoleHolders Test: "+$DC)


if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test KnowsOfRoleHolders')).Count -eq $true) 
    {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Passed</td>"
    }
    elseif(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test KnowsOfRoleHolders')).Count -eq $true) 
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Failed</font></td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Missing</font></td>"
                }

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag MachineAccount Test: "+$DC)

if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test MachineAccount')).Count -eq $true) 
    {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Passed</td>"
    }
    elseif(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test MachineAccount')).Count -eq $true) 
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Failed</font></td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Missing</font></td>"
                }

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag NCSecDesc Test: "+$DC)

if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test NCSecDesc')).Count -eq $true) 
    {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Passed</td>"
    }
    elseif(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test NCSecDesc')).Count -eq $true) 
                {
                    Add-Content $report "<td bgcolor= 'Yellow' align=center>Failed</td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor= 'Yellow' align=center>Missing</td>"
                }

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag NetLogons Test: "+$DC)

if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test NetLogons')).Count -eq $true) 
    {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Passed</td>"
    }
    elseif(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test NetLogons')).Count -eq $true) 
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Failed</font></td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Missing</font></td>"
                }

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag ObjectsReplicated: "+$DC)

if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test ObjectsReplicated')).Count -eq $true) 
    {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Passed</td>"
    }
    elseif(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test ObjectsReplicated')).Count -eq $true) 
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Failed</font></td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Missing</font></td>"
                }

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag Replications: "+$DC)

if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test Replications')).Count -eq $true) 
    {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Passed</td>"
    }
    elseif(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test Replications')).Count -eq $true) 
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Failed</font></td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Missing</font></td>"
                }

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag RIDManager: "+$DC)

if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test RidManager')).Count -eq $true) 
    {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Passed</td>"
    }
    elseif(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test RidManager')).Count -eq $true) 
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Failed</font></td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Missing</font></td>"
                }

if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test Services')).Count -eq $true) 
    {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Passed</td>"
    }
    elseif(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test Services')).Count -eq $true) 
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Failed</font></td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Missing</font></td>"
                }

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag SystemLog Test: "+$DC)

if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test SystemLog')).Count -eq $true) 
    {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Passed</td>"
    }
    elseif(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test SystemLog')).Count -eq $true) 
                {
                    Add-Content $report "<td bgcolor= 'Yellow' align=center>Failed</td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor= 'Yellow' align=center>Missing</td>"
                }

Add-Content $report "</tr>" 

}


Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR><BR><BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>For environments with more than 50 Domain Controllers, no details are presented for each category of DCDiag. I suggest you check : <a href='https://blogs.technet.microsoft.com/askds/2011/03/22/what-does-dcdiag-actually-do/'>What does DCDiag actually do</a>. For better understanding of what those results mean.</td></tr></TABLE>"

add-content $report  "</CENTER>"

add-content $report "<BR><BR><BR><BR><BR><BR>"


add-content $report "<BR><A HREF='#top'>Back to the top</A><BR>"
add-content $report "<BR><TABLE BORDER='1' CELLPADDING='5'><TR><TD BGCOLOR='Silver'><A NAME='Disclaimer'><B>Disclaimer:</B></A> This report was generated using the ADxRay Powershell Script. The information provided in this report is provided 'as-is' and is intended for information purposes only. The information present at the script is licensed 'as-is'. You bear the risk of using it. The contributors give no express warranties, guarantees or conditions. You may have additional consumer rights under your local laws which this license cannot change. To the extent permitted under your local laws, the contributors exclude the implied warranties of merchantability, fitness for a particular purpose and non-infringement. Any feedback or improvements feel free to email me at: <a href='mailto:merola@outlook.com?Subject=ADxRay%20feedback' target='_top'>Claudio Merola</a></TD></TR></TABLE>"
add-content $report "<BR><TABLE BORDER='1' CELLPADDING='5'><TR><TD BGCOLOR='Silver'><A NAME='More'><B>More:</B></A> If you wish to have a better inventory and reporting regarding your Active Directory environment, Get in touch with your Microsoft representative to run an On-Demand Assessment in your Active Directory environment. On-Demand Assessment will give you a deeper view and understanding of every single issue existing in the environment. More details at: <a href='https://docs.microsoft.com/en-us/services-hub/health/'>Services Hub On-Demand Assessments</a></TD></TR></TABLE>"

add-content $report "<BR><BR><BR><BR>"


}
else
{

add-content $report "<BR><BR><BR>"

ForEach ($DC in $Global:DCs)
{

add-content $report  "<table width='50%' border='0'>" 
add-content $report  "<tr bgcolor='White'>" 
add-content $report  "<td colspan='7' height='70' align='left'>" 
add-content $report  "<H2>$DC<HR><H2>" 
add-content $report  "</td>" 
add-content $report  "</tr>" 
add-content $report  "</table>"

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag Reporting of: "+$DC)


$DCD = Import-Clixml -Path ('C:\ADxRay\Hammer\Inv_'+$DC+'.xml')


$DC = $DC.ToString()
$DC = $DC.split('.')
$DC = $DC[0]

add-content $report "<BR><BR>"

add-content $report "<CENTER>"
 
add-content $report  "<table width='85%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='40%' align='center'><B>Domain Controller Status</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>Impact</B></td>" 
Add-Content $report  "<td width='60%' align='center'><B>Description</B></td>" 


Add-Content $report "<tr>"

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag initial validation: "+$DC)

if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test Connectivity')).Count -eq $true) 
    {
            $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' passed test Connectivity') 
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test Connectivity')).Count -eq $true) 
                {
                    $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' failed test Connectivity')
                    Add-Content $report "<td bgcolor='Yellow' align=center>$Status</td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor='Yellow' align=center>......................... $DC missing test Connectivity</td>"
                }
    }

add-content $report  "<td bgcolor='White' align=center>Medium</td>"

add-content $report  "<td bgcolor='White' align=center>Initial connection validation, checks if the DC can be located in the DNS, validates the ICMP ping (1 hop), checks LDAP binding and also the RPC connection. This initial test requires <b>ICMP, LDAP, DNS</b> and <b>RPC</b> connectivity to work properly.</td>"

Add-Content $report "</tr>" 

Add-Content $report "<tr>"


Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag VerifyReference Test: "+$DC)
if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test VerifyReferences')).Count -eq $true) 
    {
            $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' passed test VerifyReferences')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test VerifyReferences')).Count -eq $true) 
                {
                    $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' failed test VerifyReferences')
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$Status</font></td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>......................... $DC missing test VerifyReferences</font></td>"
                }
    }

add-content $report  "<td bgcolor='White' align=center>High</td>"

add-content $report  "<td bgcolor='White' align=center>Validates that several attributes are present for the domain in the countainer and subcontainers in the DC objetcs. This test will fail if any attribute is missing. You can find more details regarding the attributes at '<a href='https://blogs.technet.microsoft.com/askds/2011/03/22/what-does-dcdiag-actually-do/'> What does DCDiag actually do.</a>'</td>"

Add-Content $report "</tr>" 

Add-Content $report "<tr>"

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag Advertising Test: "+$DC)

if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test Advertising')).Count -eq $true) 
    {
            $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' passed test Advertising')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test Advertising')).Count -eq $true) 
                {
                    $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' failed test Advertising')
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$Status</font></td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>......................... $DC missing test Advertising</font></td>"
                }
    }

add-content $report  "<td bgcolor='White' align=center>High</td>"

add-content $report  "<td bgcolor='White' align=center>Validates this Domain Controller can be correctly located through the KDC service. It does not validate the Kerberos tickets answer or the communication through the <b>TCP</b> and <b>UDP</b> port <b>88</b>.</td>"

Add-Content $report "</tr>" 

Add-Content $report "<tr>"

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag FrsEvent: "+$DC)

if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test FrsEvent')).Count -eq $true) 
    {
            $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' passed test FrsEvent')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test FrsEvent')).Count -eq $true) 
                {
                    $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' failed test FrsEvent')
                    Add-Content $report "<td bgcolor='Yellow' align=center>$Status</td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor='Yellow' align=center>......................... $DC missing test FrsEvent</td>"
                }
    }

add-content $report  "<td bgcolor='White' align=center>Medium</td>"

add-content $report  "<td bgcolor='White' align=center>Checks if theres any errors in the event logs regarding FRS replication. If running Windows Server 2008 R2 or newer on all Domain Controllers is possible SYSVOL were already migrated to DFSR, in this case errors found here can be ignored.</td>"

Add-Content $report "</tr>" 

Add-Content $report "<tr>"

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag DFSREvent Test: "+$DC)

if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test DFSREvent')).Count -eq $true) 
    {
            $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' passed test DFSREvent')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test DFSREvent')).Count -eq $true) 
                {
                    $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' failed test DFSREvent')
                    Add-Content $report "<td bgcolor='Yellow' align=center>$Status</td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor='Yellow' align=center>......................... $DC missing test DFSREvent</td>"
                }
    }

add-content $report  "<td bgcolor='White' align=center>Medium</td>"

add-content $report  "<td bgcolor='White' align=center>Checks if theres any errors in the event logs regarding DFSR replication. If running Windows Server 2008 or older on all Domain Controllers is possible SYSVOL is still using FRS, and in this case errors found here can be ignored. Obs. is highly recommended to migrate SYSVOL to DFSR.</td>"

Add-Content $report "</tr>" 

Add-Content $report "<tr>"

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag SysvolCheck Test: "+$DC)

if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test SysVolCheck')).Count -eq $true) 
    {
            $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' passed test SysVolCheck')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test SysVolCheck')).Count -eq $true) 
                {
                    $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' failed test SysVolCheck')
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$Status</font></td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>......................... $DC missing test SysVolCheck</font></td>"
                }
    }

add-content $report  "<td bgcolor='White' align=center>High</td>"

add-content $report  "<td bgcolor='White' align=center>Validates if the registry key <b>'HKEY_Local_Machine\System\CurrentControlSet\Services\Netlogon\Parameters\SysvolReady=1'</b> exist. This registry has to exist with value '1' for the DC´s SYSVOL to be advertised.</td>"

Add-Content $report "</tr>" 

Add-Content $report "<tr>"

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag KccEvent Test: "+$DC)

if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test KccEvent')).Count -eq $true) 
    {
            $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' passed test KccEvent')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test KccEvent')).Count -eq $true) 
                {
                    $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' failed test KccEvent')
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$Status</font></td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>......................... $DC missing test KccEvent</font></td>"
                }
    }

add-content $report  "<td bgcolor='White' align=center>High</td>"

add-content $report  "<td bgcolor='White' align=center>Validates through KCC there were no errors in the <b>Event Viewer > Applications and Services Logs > Directory Services</b> event log in the past 15 minutes (default time).</td>"

Add-Content $report "</tr>" 

Add-Content $report "<tr>"

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag KnowsOfRoleHolders Test: "+$DC)


if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test KnowsOfRoleHolders')).Count -eq $true) 
    {
            $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' passed test KnowsOfRoleHolders')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test KnowsOfRoleHolders')).Count -eq $true) 
                {
                    $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' failed test KnowsOfRoleHolders')
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$Status</font></td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>......................... $DC missing test KnowsOfRoleHolders</font></td>"
                }
    }

add-content $report  "<td bgcolor='White' align=center>High</td>"

add-content $report  "<td bgcolor='White' align=center>Checks if this Domain Controller is aware of which DC (or DCs) hold the <b>FSMOs</b>.</td>"

Add-Content $report "</tr>" 

Add-Content $report "<tr>"

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag MachineAccount Test: "+$DC)



if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test MachineAccount')).Count -eq $true) 
    {
            $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' passed test MachineAccount')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test MachineAccount')).Count -eq $true) 
                {
                    $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' failed test MachineAccount')
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$Status</font></td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>......................... $DC missing test MachineAccount</font></td>"
                }
    }

add-content $report  "<td bgcolor='White' align=center>High</td>"

add-content $report  "<td bgcolor='White' align=center>Checks if this computer account exist in Active Directory and the main attributes are set. If this validation reports error. the following parameters of <b>DCDIAG</b> might help: <b>/RecreateMachineAccount</b> and <b>/FixMachineAccount</b>.</td>"

Add-Content $report "</tr>" 

Add-Content $report "<tr>"

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag NCSecDesc Test: "+$DC)

if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test NCSecDesc')).Count -eq $true) 
    {
            $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' passed test NCSecDesc')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test NCSecDesc')).Count -eq $true) 
                {
                    $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' failed test NCSecDesc')
                    Add-Content $report "<td bgcolor= 'Yellow' align=center>$Status</td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor= 'Yellow' align=center>......................... $DC missing test NCSecDesc</td>"
                }
    }

add-content $report  "<td bgcolor='White' align=center>Medium</td>"

add-content $report  "<td bgcolor='White' align=center>Validates if permissions are correctly set in this Domain Controller for all naming contexts. Those permissions directly affect replication´s health.</td>"

Add-Content $report "</tr>" 

Add-Content $report "<tr>"

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag NetLogons Test: "+$DC)

if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test NetLogons')).Count -eq $true) 
    {
            $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' passed test NetLogons')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test NetLogons')).Count -eq $true) 
                {
                    $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' failed test NetLogons')
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$Status</font></td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>......................... $DC missing test NetLogons</font></td>"
                }
    }

add-content $report  "<td bgcolor='White' align=center>High</td>"

add-content $report  "<td bgcolor='White' align=center>Validates if core security groups (including administrators and Authenticated Users) can connect and read NETLOGON and SYSVOL folders. It also validates access to IPC$. which can lead to failures in organizations that disable IPC$.</td>"

Add-Content $report "</tr>" 

Add-Content $report "<tr>"

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag ObjectsReplicated: "+$DC)

if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test ObjectsReplicated')).Count -eq $true) 
    {
            $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' passed test ObjectsReplicated')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test ObjectsReplicated')).Count -eq $true) 
                {
                    $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' failed test ObjectsReplicated')
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$Status</font></td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>......................... $DC missing test ObjectsReplicated</font></td>"
                }
    }

add-content $report  "<td bgcolor='White' align=center>High</td>"

add-content $report  "<td bgcolor='White' align=center>Checks the replication health of core objects and attributes.</td>"

Add-Content $report "</tr>" 

Add-Content $report "<tr>"

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag Replications: "+$DC)

if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test Replications')).Count -eq $true) 
    {
            $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' passed test Replications')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test Replications')).Count -eq $true) 
                {
                    $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' failed test Replications')
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$Status</font></td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>......................... $DC missing test Replications</font></td>"
                }
    }

add-content $report  "<td bgcolor='White' align=center>High</td>"

add-content $report  "<td bgcolor='White' align=center>Makes a deep validation to check the main replication for all naming contexts in this Domain Controller.</td>"

Add-Content $report "</tr>" 

Add-Content $report "<tr>"

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag RIDManager: "+$DC)

if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test RidManager')).Count -eq $true) 
    {
            $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' passed test RidManager')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test RidManager')).Count -eq $true) 
                {
                    $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' failed test RidManager')
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$Status</font></td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>......................... $DC missing test RidManager</font></td>"
                }
    }

add-content $report  "<td bgcolor='White' align=center>High</td>"

add-content $report  "<td bgcolor='White' align=center>Validates that this Domain Controller and locate and contact the RID Master FSMO role holder.</td>"

Add-Content $report "</tr>" 

Add-Content $report "<tr>"

if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test Services')).Count -eq $true) 
    {
            $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' passed test Services')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test Services')).Count -eq $true) 
                {
                    $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' failed test Services')
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$Status</font></td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>......................... $DC missing test Services</font></td>"
                }
    }

add-content $report  "<td bgcolor='White' align=center>High</td>"

add-content $report  "<td bgcolor='White' align=center>Validates if the core Active Directory services are running in this Domain Controller. The services verified are: <b>RPCSS, EVENTSYSTEM, DNSCACHE, ISMSERV, KDC, SAMSS, WORKSTATION, W32TIME, NETLOGON, NTDS</b> (in case Windows Server 2008 or newer) and <b>DFSR</b> (if SYSVOL is using DFSR).</td>"

Add-Content $report "</tr>" 

Add-Content $report "<tr>"

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting DCDiag SystemLog Test: "+$DC)

if(($DCD.DCDiag | Select-String -Pattern ($DC +' passed test SystemLog')).Count -eq $true) 
    {
            $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' passed test SystemLog')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCD.DCDiag | Select-String -Pattern ($DC +' failed test SystemLog')).Count -eq $true) 
                {
                    $Status = $DCD.DCDiag | Select-String -Pattern ($DC +' failed test SystemLog')
                    Add-Content $report "<td bgcolor= 'Yellow' align=center>$Status</td>"
                }
                else
                {
                    Add-Content $report "<td bgcolor= 'Yellow' align=center>......................... $DC missing test SystemLog</td>"
                }
    }

add-content $report  "<td bgcolor='White' align=center>Low</td>"

add-content $report  "<td bgcolor='White' align=center>Checks if there is any erros in the <b>'Event Viewer > System'</b> event log in the past 60 minutes. Since the System event log records data from many places, errors reported here may lead to false positive and must be investigated further. The impact of this validation is marked as 'Low' because is very rare to find a DC without any 'errors' in the System's Event Log.</td>"

Add-Content $report "</tr>" 

Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR><BR><BR>"

}

add-content $report "<BR><BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>For more details regarding the Domain Controller Diagnostic tool, check '<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731968(v%3Dws.11)'>DCDiag</a>'.Also, verify '<a href='https://blogs.technet.microsoft.com/askds/2011/03/22/what-does-dcdiag-actually-do/'>What does DCDiag actually do</a>' for further understanding of what those results mean. </td></tr></TABLE>"

add-content $report  "</CENTER>"

add-content $report "<BR><BR><BR><BR><BR><BR>"


add-content $report "<BR><A HREF='#top'>Back to the top</A><BR>"
add-content $report "<BR><TABLE BORDER='1' CELLPADDING='5'><TR><TD BGCOLOR='Silver'><A NAME='Disclaimer'><B>Disclaimer:</B></A> This report was generated using the ADxRay Powershell Script. The information provided in this report is provided 'as-is' and is intended for information purposes only. The information present at the script is licensed 'as-is'. You bear the risk of using it. The contributors give no express warranties, guarantees or conditions. You may have additional consumer rights under your local laws which this license cannot change. To the extent permitted under your local laws, the contributors exclude the implied warranties of merchantability, fitness for a particular purpose and non-infringement. Any feedback or improvements feel free to email me at: <a href='mailto:merola@outlook.com?Subject=ADxRay%20feedback' target='_top'>Claudio Merola</a></TD></TR></TABLE>"
add-content $report "<BR><TABLE BORDER='1' CELLPADDING='5'><TR><TD BGCOLOR='Silver'><A NAME='More'><B>More:</B></A> If you wish to have a better inventory and reporting regarding your Active Directory environment, Get in touch with your Microsoft representative to run an On-Demand Assessment in your Active Directory environment. On-Demand Assessment will give you a deeper view and understanding of every single issue existing in the environment. More details at: <a href='https://docs.microsoft.com/en-us/services-hub/health/'>Services Hub On-Demand Assessments</a></TD></TR></TABLE>"

add-content $report "<BR><BR><BR><BR>"


}


add-content $report "</div>"



######################################### SECURITY HEADER #############################################


add-content $report  "<div id='Security' class='tabcontent'>"

add-content $report  "<table width='100%' border='0'>" 
add-content $report  "<tr bgcolor='White'>" 
add-content $report  "<td colspan='7' height='70' align='center'>" 
add-content $report  "<font face='verdana' color='#000000' size='62'>Domain Controller's Security<HR></font>" 
add-content $report  "</td>" 
add-content $report  "</tr>" 
add-content $report  "</table>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>This section will give a detailed view of the Domain Controller's Security. This inventory is based on Microsoft´s best practices and recommendations.</td></tr></TABLE>" 

add-content $report "<BR><BR><BR>"


######################################### DCs Security Log inventory  ###############################################



<#

write-host 'Starting Domain Controller Security Log Reporting..'

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Checking if RSOP Folder already exists.")    

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Begining Domain Controller's Security Log Reporting.")   

add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>Domain Controllers Event Log Inventory ($Forest)</h3>" 
add-content $report  "</CENTER>"
add-content $report "<BR>"

add-content $report  "<table width='90%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='5%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='8%' align='center'><B>System Log Max Size (Kb)</B></td>" 
Add-Content $report  "<td width='8%' align='center'><B>Recommended Size (Kb)</B></td>"
Add-Content $report  "<td width='8%' align='center'><B>Security Log Max Size (Kb)</B></td>" 
Add-Content $report  "<td width='8%' align='center'><B>Recommended Size (Kb)</B></td>"
Add-Content $report  "<td width='8%' align='center'><B>Cleartext Password Logon Count</B></td>" 
Add-Content $report  "<td width='8%' align='center'><B>Batch job Logon Count</B></td>"
Add-Content $report  "<td width='10%' align='center'><B>Critical Security Events Found</B></td>" 

Add-Content $report "</tr>" 

$CritEvents = 0

foreach ($DC in $Global:DCs)
    {
    Try{

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Begining Event Viewer Log Inventory of:"+$DC) 
        
    $DCD = Import-Clixml -Path ('C:\ADxRay\Hammer\Inv_'+$DC+'.xml')

    $SysLogSize = $DCD.DCSysLog
    
    $SecLogSize = $DCD.DCSecLog
    
    $evt = $DCD.CriticalEvts

    $evtclearpw = $DCD.DCCleEvts
    $evtbatch = $DCD.DCBatEvts

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Log sizes adquired:"+$SysLogSize+" , "+$SecLogSize+" and "+$ADLogSize) 

    $Domain = $DCD.Domain
    $DCHostName = $DC
    $DCSysLog = '{0:N0}' -f $SysLogSize
    $SysRec = '{0:N0}' -f (1002400)
    $DCSecLog = '{0:N0}' -f $SecLogSize
    $SecRec = '{0:N0}' -f (4194240)
    $DCEvt = $evt
    
    Add-Content $report "<tr>"

    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DCHostname</td>" 

        if ($SysLogSize.MaximumKilobytes -ge 1002400)
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>$DCSysLog</td>"  
        }
    else
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$DCSysLog</font></td>"   
        }

    Add-Content $report "<td bgcolor='White' align=center>$SysRec</td>" 

        if ($SecLogSize.MaximumKilobytes -ge 4194240)
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>$DCSecLog</td>"  
        }
    else
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$DCSecLog</font></td>"   
        }

    Add-Content $report "<td bgcolor='White' align=center>$SecRec</td>" 

        if ($evtclearpw -eq '' -or $evtclearpw -eq 0)
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>0</td>"  
        }
    else
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$evtclearpw</font></td>"   
        }

        if ($evtbatch -eq '' -or $evtbatch -eq 0)
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>0</td>"  
        }
    else
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$evtbatch</font></td>"   
        }

        if ($DCEvt -ge 1)
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$DCEvt</font></td>" 
            $CritEvents ++  
        }
    else
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>$DCEvt</td>"    
        }
        Add-Content $report "</tr>" 
        Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - End of server:"+$DC) 
}
Catch{
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Err - The following error ocurred during catcher: "+$_.Exception.Message) 
}
}


Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

if ($CritEvents -ge 1)
{
add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td bgcolor= 'Red' align=center><font color='#FFFFFF'>Critical Security Events were found in this environment! Investigate further following Microsoft´s <a href='https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor'>Events to Monitor in Active Directory</a>. </font></td></tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

}

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Event log configuration must be a top priority. Often when those configurations are noticed is already too late. Make sure at least Security and System Events are adjusted to a regular size. Even when you have a log centralization solution, in a catastrophic event you may lose access to that server, or even the server, and important logs may be lost. A good event size on the Domain Controllers Is a good strategy to be safe in a situation like that. Those recommendations were set based on the following pages: <a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd349798(v=ws.10)'>Event Log</a> and <a href='https://docs.microsoft.com/en-us/windows/client-management/mdm/diagnosticlog-csp'>DiagnosticLog CSP</a>. If you don’t have a log centralization infrastructure in place. Check my other Github project <a href='https://github.com/ClaudioMerola/HFServerEventsV2'>HF Event Server</a>. This is a free project that configures a log centralization infrastructure powered by Elasticsearch and is (100% free).</td></tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR><BR><BR><BR><BR><BR>"

#>




######################################### DCs Security BACKUP inventory  ###############################################


write-host 'Domain Controllers Backup Reporting..'

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Begining Domain Controller's Backup Reporting.")   

add-content $report  "<CENTER>"
add-content $report  "<h3>Active Directory Backups ($Forest)</h3>" 
add-content $report  "</CENTER>"
add-content $report "<BR>"

add-content $report "<CENTER>"
 
add-content $report  "<table width='60%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='5%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Latest Backup Date</B></td>" 

 
Add-Content $report "</tr>" 

$CritEvents = 0
$NoBackups = 0
Remove-Variable Backups

foreach ($DC in $Global:DCs) 
    {
    Try{

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Begining Reporting of Active Backups:"+$DC)
        
    $DCD = Import-Clixml -Path ('C:\ADxRay\Hammer\Inv_'+$DC+'.xml')

    $Backup = (($DCD.Backup | Select-String -Pattern [datetime])[2]).ToString().split() | Select-String -Pattern "\d{4}-\d{2}-\d{2}"

    $Backup = [datetime]::parseexact($Backup, 'yyyy-MM-dd',$null)

    $oldbkp = 0
    if ((New-TimeSpan -Start $Backup -End (Get-Date)).Days -ge 30) {$oldbkp = 1}

    $Backup = $Backup.tostring('MM-dd-yyyy')

    $Domain = $DCD.Domain

    $DCHostName = $DC

    if (!$Backup) {$NoBackups ++}

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Latest backup on: '+$DCHostname +'. was on:"+$Backup)
    
    Add-Content $report "<tr>"

    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>"
    Add-Content $report "<td bgcolor='White' align=center>$DCHostname</td>"

    if ($oldbkp -eq 1)
    {
    $CritEvents ++
    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$Backup</font></td>" 
    }
    else 
    {
    Add-Content $report "<td bgcolor='White' align=center>$Backup</td>" 
    }

    Add-Content $report "</tr>" 
    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - End of BackUp for server:"+$DC)
}
Catch{
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Err - The following error ocurred during reporting: "+$_.Exception.Message)
}
}

Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

if ($CritEvents -ge 1)
{
add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td bgcolor= 'Red' align=center><font color='#FFFFFF'>Outdated backups were found in the environment. Verify and make sure backups are been run in the Domain Controllers above.</font></td></tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

}

if ($NoBackups -ge 1)
{
add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td bgcolor= 'Red' align=center><font color='#FFFFFF'>No Backups were found at all!! Check the current backup policies and make sure this environment is been backed up correctly as soon as possible.</font></td></tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

}

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Keeping a regular Windows Servers Backup routine is important to make sure that, if a catastrophic event happens you are covered. Microsoft recommends that you keep Full Server Backups, because it can be restored to different hardware or a different operating system instance. Windows Server Backup is included in Windows Server (but is not enable by default). Consult: <a href=https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-backing-up-a-full-server'>AD Forest Recovery - Backing up a full server</a> for more details.</td></tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR><BR><BR><BR><BR><BR>"




######################################### DCs Security PRINT SPOOLER inventory  ###############################################


write-host 'Domain Controllers Print Spooler Reporting..'

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Begining Domain Controller's Print Spooler Reporting.")   

add-content $report  "<CENTER>"
add-content $report  "<h3>Print Spooler Service Status ($Forest)</h3>" 
add-content $report  "</CENTER>"
add-content $report "<BR>"

add-content $report "<CENTER>"

add-content $report  "<table width='60%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='5%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Print Spooler Status</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Print Spooler Startup Mode</B></td>"


Add-Content $report "</tr>" 

foreach ($DC in $Global:DCs) 
    {
    Try{

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Begining Print Spooler Reporting of:"+$DC) 
        
    $DCD = Import-Clixml -Path ('C:\ADxRay\Hammer\Inv_'+$DC+'.xml')

    $State = $DCD.Spooler_State

    $Startup = $DCD.Spooler_StartMode 

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Print Spooler Status:"+$State)
    
    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Print Spooler Startup Mode:"+$Startup) 

    $Domain = $DCD.Domain
    $DCHostName = $DC
    
    Add-Content $report "<tr>"

    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DCHostname</td>" 

    if ($State -eq 'Running')
    {
    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$State</font></td>" 
    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$Startup</font></td>" 
    }
    else 
    {
    Add-Content $report "<td bgcolor='Lime' align=center>$State</td>" 
    Add-Content $report "<td bgcolor='Lime' align=center>$Startup</td>" 
    }

    Add-Content $report "</tr>" 
    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - End of Print Spooler Reporting for server:"+$DC) 
}
Catch{
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Err - The following error ocurred during reporting: "+$_.Exception.Message) 
}
}


Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>According to Microsoft: ‘While seemingly harmless, any authenticated user can remotely connect to a domain controller print spooler service, and request an update on new print jobs. In addition, users can tell the domain controller to send the notification to the system with unconstrained delegation. These actions test the connection and expose the domain controller computer account credential (Print spooler is owned by SYSTEM).’. <a href=’https://docs.microsoft.com/en-us/azure-advanced-threat-protection/atp-cas-isp-print-spooler'>Security assessment: Domain controllers with Print spooler service available</a>. For a deeper insight and better security view, monitor and protection of your domain controller’s environment give a look and perhaps a try on Azure Advanced Treat Protection (<a href=’https://docs.microsoft.com/en-us/azure-advanced-threat-protection/what-is-atp>What is Azure Advanced Threat Protection?</a>).</td></tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR><BR><BR><BR><BR><BR>"



######################################### DCs Security HotFix inventory  ###############################################


write-host 'Domain Controllers HotFix Reporting..'

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Begining Domain Controller's Hotfix Reporting.")   

add-content $report  "<CENTER>"
add-content $report  "<h3>Installed HotFix ($Forest)</h3>" 
add-content $report  "</CENTER>"
add-content $report "<BR>"

add-content $report "<CENTER>"
 
add-content $report  "<table width='60%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='5%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Latest Installed HotFix</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Installation Date</B></td>"

 
Add-Content $report "</tr>" 

$CritEvents = 0

foreach ($DC in $Global:DCs)
    {
    Try{

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Begining HotFix Inventory of:"+$DC) 
        
    $DCD = Import-Clixml -Path ('C:\ADxRay\Hammer\Inv_'+$DC+'.xml')

    $Update = $DCD.Hotfix

    $Result = $Update[0] 

    $HFDate = $Result.InstalledOn.ToShortDateString()

    $HFID = $Result.HotFixID

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Latest Hotfix installed on:"+$HFDate)
    
    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Latest Hotfix installed:"+$HFID) 

    $Domain = $DCD.Domain
    $DCHostName = $DC
    
    Add-Content $report "<tr>"

    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DCHostname</td>" 

    if ((New-TimeSpan -Start $HFDate -End (Get-Date)).Days -ge 60)
    {
    $CritEvents ++
    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$HFID</font></td>" 
    Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$HFDate</font></td>" 
    }
    else 
    {
    Add-Content $report "<td bgcolor='White' align=center>$HFID</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$HFDate</td>" 
    }
   
    Add-Content $report "</tr>" 
    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - End of Hotfix Inventory for server:"+$DC) 
}
Catch{
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Err - The following error ocurred during catcher: "+$_.Exception.Message) 
}
}


Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"


if ($CritEvents -ge 1)
{
add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td bgcolor= 'Red' align=center><font color='#FFFFFF'>Outdated Domain Controllers were found! Since 2015 Microsoft make rollup updates available in a monthly basis. Update the reported servers as soon as possible!</font></td></tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

}


add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Keeping Windows Servers up to date is one of the most important tasks regarding security. Make sure to keep Windows Servers hotfix current with latest Microsoft updates: <a href='https://support.microsoft.com/en-us/help/4464619/windows-10-update-history'>Microsoft Windows Server 2016/2019</a>, <a href='https://support.microsoft.com/en-us/help/4009470/windows-8-1-windows-server-2012-r2-update-history'>Microsoft Windows Server 2012 R2</a>, <a href='https://support.microsoft.com/en-us/help/4009471/windows-server-2012-update-history'>Microsoft Windows Server 2012</a> and <a href='https://support.microsoft.com/en-us/help/4009469/windows-7-sp1-windows-server-2008-r2-sp1-update-history'>Microsoft Windows Server 2008 R2 SP1</a>. If you are still running Domain Controllers with Windows Server 2012 R2 and below, please consider upgrading those servers as soon as possible.</td></tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR><BR><BR><BR><BR><BR>"





######################################### DCs Security GPOs inventory  ###############################################


$SecOptions = 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec','MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\allownullsessionfallback','MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity','MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM','MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin','MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\sealsecurechannel','MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption','MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization','MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel','MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity','MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\requiresecuritysignature','MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec','MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs','MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess','MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword','MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser','MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash','MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy','MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature','MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken','MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode','MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\signsecurechannel','MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\requirestrongkey','MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection','MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\requiresignorseal','MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse','MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous','MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths','MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA'

$SecPolicies = 'Prevent enabling lock screen camera','Prevent enabling lock screen slide show','Configure SMB v1 client driver','Configure SMB v1 server','Enable Structured Exception Handling Overwrite Protection (SEHOP)','Extended Protection for LDAP Authentication (Domain Controllers only)','NetBT NodeType configuration','WDigest Authentication (disabling may require KB2871997)','MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)','MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)','MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes','MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers','Turn off multicast name resolution','Enable insecure guest logons','Windows Defender Firewall: Protect all network connections','Hardened UNC Paths','Encryption Oracle Remediation','Remote host allows delegation of non-exportable credentials','Boot-Start Driver Initialization Policy','Configure registry policy processing','Enumeration policy for external devices incompatible with Kernel DMA Protection','Disallow Autoplay for non-volume devices','Set the default behavior for AutoRun','Turn off Autoplay','Configure enhanced anti-spoofing','Specify the maximum log file size (KB)','Do not allow passwords to be saved','Do not allow drive redirection','Always prompt for password upon connection','Require secure RPC communication','Set client connection encryption level','Prevent downloading of enclosures','Allow indexing of encrypted files','Configure Windows Defender SmartScreen','Allow Windows Ink Workspace','Allow user control over installs','Always install with elevated privileges','Sign-in and lock last interactive user automatically after a restart','Turn on PowerShell Script Block Logging','Allow Basic authentication','Allow unencrypted traffic','Disallow Digest authentication','Allow Basic authentication','Allow unencrypted traffic','Disallow WinRM from storing RunAs credentials'

$SecUsrR = 'SeCreateGlobalPrivilege','SeImpersonatePrivilege','SeCreateTokenPrivilege','SeTakeOwnershipPrivilege','SeRestorePrivilege','SeDebugPrivilege','SeInteractiveLogonRight','SeCreatePagefilePrivilege','SeLockMemoryPrivilege','SeNetworkLogonRight','SeCreatePermanentPrivilege','SeTcbPrivilege','SeRemoteShutdownPrivilege','SeBackupPrivilege','SeEnableDelegationPrivilege','SeSystemEnvironmentPrivilege','SeRemoteInteractiveLogonRight','SeLoadDriverPrivilege','SeTrustedCredManAccessPrivilege','SeProfileSingleProcessPrivilege','SeManageVolumePrivilege'

$SecReg = 'SYSTEM\CurrentControlSet\Policies\EarlyLaunch','Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths','Software\Policies\Microsoft\Windows\WinRM\Service','SYSTEM\CurrentControlSet\Services\Netbt\Parameters','SYSTEM\CurrentControlSet\Control\Session Manager\kernel','Software\Policies\Microsoft\Windows\LanmanWorkstation','Software\Policies\Microsoft\Windows\WinRM\Client','Software\Policies\Microsoft\WindowsFirewall\PublicProfile','Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging','Software\Policies\Microsoft\Internet Explorer\Feeds','Software\Policies\Microsoft\WindowsFirewall\DomainProfile','Software\Microsoft\Windows\CurrentVersion\Policies\System','Software\Policies\Microsoft\Windows\Installer','SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters','Software\Policies\Microsoft\Windows NT\Terminal Services','Software\Policies\Microsoft\Windows\Kernel DMA Protection','Software\Policies\Microsoft\Windows\CredentialsDelegation','Software\Policies\Microsoft\Windows\System','SYSTEM\CurrentControlSet\Services\Tcpip\Parameters','Software\Policies\Microsoft\WindowsFirewall\PrivateProfile','Software\Policies\Microsoft\WindowsInkWorkspace','Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}','Software\Policies\Microsoft\Windows\Personalization','Software\Policies\Microsoft\WindowsFirewall','SYSTEM\CurrentControlSet\Services\NTDS\Parameters','Software\Policies\Microsoft\Windows\EventLog\Security','Software\Policies\Microsoft\Windows\Windows Search','Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters','SYSTEM\CurrentControlSet\Services\MrxSmb10','Software\Policies\Microsoft\Windows\Safer','Software\Policies\Microsoft\Windows\EventLog\Application','Software\Policies\Microsoft\Windows\Explorer','Software\Policies\Microsoft\Biometrics\FacialFeatures','SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest','Software\Policies\Microsoft\Windows\EventLog\System','Software\Microsoft\Windows\CurrentVersion\Policies\Explorer','SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'

$SecAud = 'Audit Audit Policy Change','Audit Other Object Access Events','Audit Process Creation','Audit MPSSVC Rule-Level Policy Change','Audit Security State Change','Audit Directory Service Changes','Audit Sensitive Privilege Use','Audit System Integrity','Audit Computer Account Management','Audit Other System Events','Audit Security Group Management','Audit Kerberos Service Ticket Operations','Audit Directory Service Access','Audit Other Policy Change Events','Audit Authentication Policy Change','Audit File Share','Audit Account Lockout','Audit Special Logon','Audit Security System Extension','Audit Removable Storage','Audit Kerberos Authentication Service','Audit Logon','Audit Detailed File Share','Audit Other Account Management Events','Audit Credential Validation','Audit User Account Management','Audit Other Logon/Logoff Events'

$UsrRRec = 'SeDenyBatchLogonRight','SeDenyRemoteInteractiveLogonRight','SeDenyNetworkLogonRight','SeDenyServiceLogonRight'

write-host 'Domain Controller Security Policies Reporting..'


add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>Domain Controllers Security Group Policies ($Forest)</h3>" 
add-content $report  "</CENTER>"
add-content $report "<BR>"
 
add-content $report  "<table width='90%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='5%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='8%' align='center'><B>Missing Security Options Settings</B></td>" 
Add-Content $report  "<td width='8%' align='center'><B>Missing Policies Settings</B></td>"
Add-Content $report  "<td width='8%' align='center'><B>Missing Audit Settings</B></td>"
Add-Content $report  "<td width='8%' align='center'><B>Missing User Right Assignment Settings</B></td>"
Add-Content $report  "<td width='8%' align='center'><B>Missing Security Registry Settings</B></td>" 
Add-Content $report  "<td width='8%' align='center'><B>Missing Firewall Settings</B></td>"


Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting Domain Controller Security Policies Reporting") 

Add-Content $report "</tr>" 


foreach ($DC in $Global:DCs)
    {
    try {
    $DCD = Import-Clixml -Path ('C:\ADxRay\Hammer\Inv_'+$DC+'.xml')
    
    $Domain = $DCD.Domain
    $DCHostName = $DC


    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Reading RSOP result for: " +$DC) 
    [xml]$XmlDocument = Get-Content -Path ("C:\ADxRay\Hammer\RSOP_"+$DC+".xml")


    Add-Content $report "<tr>"

    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DCHostname</td>" 


    $SecCount = 0

    $secs = $XmlDocument.Rsop.ComputerResults.ExtensionData.Extension.SecurityOptions.KeyName

    Foreach ($sec in $SecOptions){
    if ($sec -notin $secs)
    {
        $SecCount ++
    }
    }

    $PolCount = 0

    $Pols = $XmlDocument.Rsop.ComputerResults.ExtensionData.Extension.Policy.Name

    Foreach ($Pol in $SecPolicies){
    if ($Pol -notin $Pols)
    {
        $PolCount ++
    }
    }

    $UsrRCount = 0

    $UsrRs = $XmlDocument.Rsop.ComputerResults.ExtensionData.Extension.UserRightsAssignment.Name

    Foreach ($UsrR in $SecUsrR){
    if ($UsrR -notin $UsrRs)
    {
        $UsrRCount ++
    }
    }

    $RegCount = 0

    $Regs = $XmlDocument.Rsop.ComputerResults.ExtensionData.Extension.RegistrySetting.KeyPath

    Foreach ($reg in $SecReg){
    if ($reg -notin $Regs)
    {
        $RegCount ++
    }
    }

    $AudCount = 0
    
    $Auds = $XmlDocument.Rsop.ComputerResults.ExtensionData.Extension.AuditSetting.SubCategoryName

    Foreach ($aud in $SecAud){
    if ($aud -notin $Auds)
    {
        $AudCount ++
    }
    }


    $FWCount = 0

    $DomFirewall = $XmlDocument.Rsop.ComputerResults.ExtensionData.Extension.DomainProfile.EnableFirewall.Value
    $PubFirewall = $XmlDocument.Rsop.ComputerResults.ExtensionData.Extension.PublicProfile.EnableFirewall.Value
    $PriFirewall = $XmlDocument.Rsop.ComputerResults.ExtensionData.Extension.PrivateProfile.EnableFirewall.Value


    if ($DomFirewall -ne $True)
    {
    $FWCount ++
    }
    if ($PubFirewall -ne $True)
    {
    $FWCount ++
    }
    if ($PriFirewall -ne $True)
    {
    $FWCount ++
    }

    if ($SecCount -ge 1)
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$SecCount</font></td>" 
        }
    else
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>$SecCount</td>"    
        }

    if ($PolCount -ge 1)
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$PolCount</font></td>" 
        }
    else
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>$PolCount</td>"    
        }

    if ($AudCount -ge 1)
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$AudCount</font></td>" 
        }
    else
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>$AudCount</td>"    
        }

    if ($UsrRCount -ge 1)
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$UsrRCount</font></td>" 
        }
    else
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>$UsrRCount</td>"    
        }

    if ($RegCount -ge 1)
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$RegCount</font></td>" 
        }
    else
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>$RegCount</td>"    
        }

    if ($FWCount -ge 1)
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$FWCount</font></td>" 
        }
    else
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>$FWCount</td>"    
        }

        Add-Content $report "</tr>" 
}
Catch{
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors found -------------")
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Err - The following error ocurred during catcher: "+$_.Exception.Message) 
}

}

Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

if ($SecCount -ge 1 -or $PolCount -ge 1 -or $UsrRCount -ge 1 -or $RegCount -ge 1 -or $FWCount -ge 1)
{

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td bgcolor= 'Red' align=center><font color='#FFFFFF'>Some of Security Policies recommended by Microsoft were not found in those Domain Controllers. Download the latest Security Baseline and apply them in the environment for Workstations, Member Servers and Domain Controllers: <a href='https://www.microsoft.com/en-us/download/details.aspx?id=55319'>Microsoft Security Compliance Toolkit 1.0</a>. Be careful when applying the Microsoft's Security Baseline in the environment, as some settings may impact the overall experience of end users. Precaution is recommended and testing everything upfront might be a good idea.</font></td></tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

}

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>This analysis is based on the Resultant Set of Policies applied on those Domain Controllers versus Microsoft´s baseline security standards. Microsoft recommends the use of security baseline GPOs (<a href='https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-final-for-windows-10-v1909-and-windows-server/ba-p/1023093'>Security baseline (FINAL) for Windows 10 v1909 and Windows Server v1909</a>) in the environment, specially on Domain Controllers. Keep your environment protected with the lastest security baseline!</tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR><BR><BR><BR><BR><BR>"





######################################### DCs Security User Rights Assignments inventory  ###############################################



add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>User Rights Assignments ($Forest)</h3>" 
add-content $report  "</CENTER>"
add-content $report "<BR>"
 
add-content $report  "<table width='90%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='5%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='15%' align='center'><B>Deny access to this computer from the network</B></td>" 
Add-Content $report  "<td width='15%' align='center'><B>Deny log on as a batch job</B></td>"
Add-Content $report  "<td width='15%' align='center'><B>Deny log on as a service</B></td>"
Add-Content $report  "<td width='15%' align='center'><B>Deny log on through Remote Desktop Services</B></td>"

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting Domain Controller User Rights Assignments reporting") 

Add-Content $report "</tr>" 

foreach ($DC in $Global:DCs)
    {
    try {
    $DCD = Import-Clixml -Path ('C:\ADxRay\Hammer\Inv_'+$DC+'.xml')

    $Domain = $DCD.Domain
    $DCHostName = $DC

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting Domain Controller User Rights Assignments on the server: "+$DC) 

    [xml]$XmlDocument = Get-Content -Path ("C:\ADxRay\Hammer\RSOP_"+$DC+".xml")

    $us = $XmlDocument.Rsop.ComputerResults.ExtensionData.Extension.UserRightsAssignment | Where-Object {$_.Name -eq 'SeDenyRemoteInteractiveLogonRight' -or $_.Name -eq 'SeDenyBatchLogonRight' -or $_.Name -eq 'SeDenyNetworkLogonRight' -or $_.Name -eq 'SeDenyServiceLogonRight'}

    $dnsvc = ''
    $dnnet = ''
    $dnbat = ''
    $dnrdp = ''

    $dnsvc = $us | Where-Object {$_.Name -eq 'SeDenyServiceLogonRight'}
    $dnsvc = $dnsvc.Member.Name.'#text'
    $dnnet = $us | Where-Object {$_.Name -eq 'SeDenyNetworkLogonRight'}
    $dnnet = $dnnet.Member.Name.'#text'
    $dnbat = $us | Where-Object {$_.Name -eq 'SeDenyBatchLogonRight'}
    $dnbat = $dnbat.Member.Name.'#text'
    $dnrdp = $us | Where-Object {$_.Name -eq 'SeDenyRemoteInteractiveLogonRight'}
    $dnrdp = $dnrdp.Member.Name.'#text'

    Add-Content $report "<tr>"

    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DCHostname</td>" 

    if ($dnnet -like '*\Administrator')
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>$dnnet</td>"
        }
    else
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$dnnet</font></td>"     
        }

    if ($dnbat -like '*\Administrator')
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>$dnbat</td>"
        }
    else
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$dnbat</font></td>"     
        }

    if ($dnsvc -like '*\Administrator')
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>$dnsvc</td>"  
        }
    else
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$dnsvc</font></td>"   
        }

    if ($dnrdp -like '*\Administrator')
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>$dnrdp</td>" 
        }
    else
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$dnrdp</font></td>"     
        }


Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Ending Domain Controller User Rights Assignments for: "+$DC)

    Add-Content $report "</tr>" 
}
Catch{
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors found -------------")
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Err - The following error ocurred during catcher: "+$_.Exception.Message) 
}

}

Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>According Microsoft (<a href='https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-d--securing-built-in-administrator-accounts-in-active-directory'>Appendix D: Securing Built-In Administrator Accounts in Active Directory</a>) the built-in Administrator Account should be denied logon trought network, Remote Desktop, as a batch job and as a service in all Domain Controllers in the environment.</tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR><BR><BR><BR><BR><BR>"
add-content $report "<BR><A HREF='#top'>Back to the top</A><BR>"
add-content $report "<BR><TABLE BORDER='1' CELLPADDING='5'><TR><TD BGCOLOR='Silver'><A NAME='Disclaimer'><B>Disclaimer:</B></A> This report was generated using the ADxRay Powershell Script. The information provided in this report is provided 'as-is' and is intended for information purposes only. The information present at the script is licensed 'as-is'. You bear the risk of using it. The contributors give no express warranties, guarantees or conditions. You may have additional consumer rights under your local laws which this license cannot change. To the extent permitted under your local laws, the contributors exclude the implied warranties of merchantability, fitness for a particular purpose and non-infringement. Any feedback or improvements feel free to email me at: <a href='mailto:merola@outlook.com?Subject=ADxRay%20feedback' target='_top'>Claudio Merola</a></TD></TR></TABLE>"
add-content $report "<BR><TABLE BORDER='1' CELLPADDING='5'><TR><TD BGCOLOR='Silver'><A NAME='More'><B>More:</B></A> If you wish to have a better inventory and reporting regarding your Active Directory environment, Get in touch with your Microsoft representative to run an On-Demand Assessment in your Active Directory environment. On-Demand Assessment will give you a deeper view and understanding of every single issue existing in the environment. More details at: <a href='https://docs.microsoft.com/en-us/services-hub/health/'>Services Hub On-Demand Assessments</a></TD></TR></TABLE>"

add-content $report "<BR><BR><BR><BR>"

add-content $report  "</div>" 



######################################### INVENTORY HEADER #############################################

add-content $report "<div id='Inventory' class='tabcontent'>"

add-content $report  "<table width='100%' border='0'>" 
add-content $report  "<tr bgcolor='White'>" 
add-content $report  "<td colspan='7' height='70' align='center'>" 
add-content $report  "<font face='verdana' color='#000000' size='62'>Domain Controller's Inventory<HR></font>" 
add-content $report  "</td>" 
add-content $report  "</tr>" 
add-content $report  "</table>" 

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>This section is intended to give an overall view of the <B>Domain Controller’s Installed Hardware</B> and <B>Domain Controller’s Installed Software</B>. The general consensus is that you should keep up to date hardware, drivers and firmwares and regarding software. Only very essential software should be installed on Domain Controllers. As more applications represent extra attack surfaces. And make sure that if you need to keep that software installed, that you keep them at least updated!</td></tr></TABLE>" 

add-content $report "<BR><BR><BR>"







######################################### INSTALLED HARDWARE  ###############################################


write-host 'Domain Controllers Hardware Reporting..'

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Begining Domain Controller's Hardware Reporting.")   


add-content $report  "<CENTER>"
add-content $report  "<h3>Hardware Inventory ($Forest)</h3>" 
add-content $report  "</CENTER>"
add-content $report "<BR>"


add-content $report "<CENTER>"
 
add-content $report  "<table width='90%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='8%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Total Physical Memory</B></td>"
Add-Content $report  "<td width='8%' align='center'><B>Total CPU Cores</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>% Free Space C:</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Last Boot Time</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>System Install Date</B></td>"
Add-Content $report  "<td width='25%' align='center'><B>BIOS Version</B></td>"

Add-Content $report "</tr>" 

foreach ($DC in $Global:DCs) 
    {
    Try{

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Begining Hardware Reporting of:"+$DC) 
        
    $DCD = Import-Clixml -Path ('C:\ADxRay\Hammer\Inv_'+$DC+'.xml')

    $Domain = $DCD.Domain
    $DCHostName = $DC

    $Proc = $DCD.HW_LogicalProc
    $FreeSpace = ($DCD.HW_FreeSpace | Where-Object {$_.InstanceName -eq 'c:'}).CookedValue.ToString('###.##')

    $InvMem = $DCD.HW_Mem
    $InvBoot = $DCD.HW_Boot
    $InvInst = $DCD.HW_Install
    $InvBios = $DCD.HW_BIOS

    $InvBiosDate = ($InvBios.Split(",")[1])

    $InvBiosDate = [Convert]::ToDateTime($InvBiosDate, [System.Globalization.DateTimeFormatInfo]::CurrentInfo)

    Add-Content $report "<tr>"

    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DCHostName</td>" 

    Add-Content $report "<td bgcolor='White' align=center>$InvMem</td>"
    Add-Content $report "<td bgcolor='White' align=center>$Proc</td>"

    if($FreeSpace -le 10)
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$FreeSpace</font></td>"
        }
        else
        {
            Add-Content $report "<td bgcolor='White' align=center>$FreeSpace</td>"
        }


    Add-Content $report "<td bgcolor='White' align=center>$InvBoot</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$InvInst</td>" 
    if((New-TimeSpan -Start $InvBiosDate -End (Get-Date)).TotalDays -ge 365)
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$InvBios</font></td>"
        }
        else
        {
            Add-Content $report "<td bgcolor='White' align=center>$InvBios</td>"
        }
   
    Add-Content $report "</tr>" 

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - End of Hardware Reporting for server:"+$DC) 
}
Catch{
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Err - The following error ocurred during Reporting: "+$_.Exception.Message) 
}
}

Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Make sure to eventually restart your servers, and keep firmware and drivers updated. </td></tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR><BR><BR><BR><BR><BR>"



######################################### INSTALLED SOFTWARES  ###############################################


write-host 'Domain Controllers Software Reporting..'

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Begining Domain Controller's Installed Software Reporting.")   

add-content $report  "<CENTER>"
add-content $report  "<h3>Software Inventory ($Forest)</h3>" 
add-content $report  "</CENTER>"
add-content $report "<BR>"


add-content $report "<CENTER>"
 
add-content $report  "<table width='90%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='8%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='15%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='25%' align='center'><B>Installed Softwares</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>Architecture</B></td>" 
Add-Content $report  "<td width='8%' align='center'><B>Version</B></td>"
Add-Content $report  "<td width='10%' align='center'><B>Publisher</B></td>"
Add-Content $report  "<td width='10%' align='center'><B>Search Known vulnerabilities</B></td>"

 
Add-Content $report "</tr>" 

foreach ($DC in $Global:DCs) 
    {
    Try{

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Begining Software Reporting of:"+$DC) 
        
    $DCD = Import-Clixml -Path ('C:\ADxRay\Hammer\Inv_'+$DC+'.xml')

    $Software64 = $DCD.InstalledSoftwaresx64   
    $Software86 = $DCD.InstalledSoftwaresx86

    $Domain = $DCD.Domain
    $DCHostName = $DC

    Foreach ($sw in $Software64)
    {

    if ($sw.DisplayName)
    {

    $SWD = $sw.DisplayName
    $SWDV = $sw.DisplayVersion
    $SWDP = $sw.Publisher

    $SWDLink = $SWD.replace(' ','+')
    $SWDVLink = $SWDV.replace(' ','+')
    $SWDPLink = $SWDP.replace(' ','+')


    Add-Content $report "<tr>"

    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DCHostName</td>" 

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting Reporting of:"+$SWD)

        if ($SWDP -like '*Microsoft*')
        {

            Add-Content $report "<td bgcolor='White' align=center>$SWD</td>"
            Add-Content $report "<td bgcolor='White' align=center>x64</td>" 
            Add-Content $report "<td bgcolor='White' align=center>$SWDV</td>" 
            Add-Content $report "<td bgcolor='White' align=center>$SWDP</td>" 
            Add-Content $report "<td bgcolor='White' align=center><a href='https://www.cvedetails.com/version-search.php?vendor=$SWDPLink&product=$SWDLink&version=$SWDVLink'>Search CVE Details</a></td>"

        }
    else
        {

            Add-Content $report "<td bgcolor='Red' align=center><font color='#FFFFFF'>$SWD</font></td>" 
            Add-Content $report "<td bgcolor='Red' align=center><font color='#FFFFFF'>x64</font></td>" 
            Add-Content $report "<td bgcolor='Red' align=center><font color='#FFFFFF'>$SWDV</font></td>"  
            Add-Content $report "<td bgcolor='Red' align=center><font color='#FFFFFF'>$SWDP</font></td>" 
            Add-Content $report "<td bgcolor='Red' align=center><font color='#FFFFFF'><a href='https://www.cvedetails.com/version-search.php?vendor=$SWDPLink&product=$SWDLink&version=$SWDVLink'>Search CVE Details</a></font></td>"   
        }

    Add-Content $report "</tr>" 
    }
    }
    Foreach ($sw in $Software86)
    {

    if ($sw.DisplayName)
    {

    $SWD = $sw.DisplayName
    $SWDV = $sw.DisplayVersion
    $SWDP = $sw.Publisher

    $SWDLink = $SWD.replace(' ','+')
    $SWDVLink = $SWDV.replace(' ','+')
    $SWDPLink = $SWDP.replace(' ','+')

    Add-Content $report "<tr>"

    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DCHostName</td>" 

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting Reporting of:"+$SWD)

        if ($SWDP -like '*Microsoft*')
        {

            Add-Content $report "<td bgcolor='White' align=center>$SWD</td>"
            Add-Content $report "<td bgcolor='White' align=center>x86</td>" 
            Add-Content $report "<td bgcolor='White' align=center>$SWDV</td>" 
            Add-Content $report "<td bgcolor='White' align=center>$SWDP</td>"
            Add-Content $report "<td bgcolor='White' align=center><a href='https://www.cvedetails.com/version-search.php?vendor=$SWDPLink&product=$SWDLink&version=$SWDVLink'>Search CVE Details</a></td>" 
        }
    else
        {

            Add-Content $report "<td bgcolor='Red' align=center><font color='#FFFFFF'>$SWD</font></td>" 
            Add-Content $report "<td bgcolor='Red' align=center><font color='#FFFFFF'>x86</font></td>" 
            Add-Content $report "<td bgcolor='Red' align=center><font color='#FFFFFF'>$SWDV</font></td>"  
            Add-Content $report "<td bgcolor='Red' align=center><font color='#FFFFFF'>$SWDP</font></td>"
            Add-Content $report "<td bgcolor='Red' align=center><font color='#FFFFFF'><a href='https://www.cvedetails.com/version-search.php?vendor=$SWDPLink&product=$SWDLink&version=$SWDVLink'>Search CVE Details</a></font></td>"   
        }

    Add-Content $report "</tr>" 
    }
    }

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - End of Software Reporting for server:"+$DC) 
}
Catch{
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Err - The following error ocurred during Reporting: "+$_.Exception.Message) 
}
}


Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Make sure that the software listed above are really necessary on those servers, in case you don’t have a real need to keep them. Uninstall them from the Domain Controllers as soon as possible. </td></tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR><BR><BR><BR><BR><BR>"

add-content $report "<BR><A HREF='#top'>Back to the top</A><BR>"
add-content $report "<BR><TABLE BORDER='1' CELLPADDING='5'><TR><TD BGCOLOR='Silver'><A NAME='Disclaimer'><B>Disclaimer:</B></A> This report was generated using the ADxRay Powershell Script. The information provided in this report is provided 'as-is' and is intended for information purposes only. The information present at the script is licensed 'as-is'. You bear the risk of using it. The contributors give no express warranties, guarantees or conditions. You may have additional consumer rights under your local laws which this license cannot change. To the extent permitted under your local laws, the contributors exclude the implied warranties of merchantability, fitness for a particular purpose and non-infringement. Any feedback or improvements feel free to email me at: <a href='mailto:merola@outlook.com?Subject=ADxRay%20feedback' target='_top'>Claudio Merola</a></TD></TR></TABLE>"
add-content $report "<BR><TABLE BORDER='1' CELLPADDING='5'><TR><TD BGCOLOR='Silver'><A NAME='More'><B>More:</B></A> If you wish to have a better inventory and reporting regarding your Active Directory environment, Get in touch with your Microsoft representative to run an On-Demand Assessment in your Active Directory environment. On-Demand Assessment will give you a deeper view and understanding of every single issue existing in the environment. More details at: <a href='https://docs.microsoft.com/en-us/services-hub/health/'>Services Hub On-Demand Assessments</a></TD></TR></TABLE>"

add-content $report "<BR><BR><BR><BR>"

add-content $report "</div>"




##################################### VERSION CONTROL #######################################

write-host 'ADxRay Version Check..'

$VerValid = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Merola132/ADxRay/master/Docs/VersionControl" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -TimeoutSec 5
if ($VerValid.StatusCode -eq 200) 
    {
        if (($VerValid.Content[0]+$VerValid.Content[1]+$VerValid.Content[2]) -eq $Ver) 
            {
                Write-Host ('Version: '+$Ver+' - This Version is up to date.') -ForegroundColor Green
            }
        else 
            {
                Write-Host ('Version: '+$Ver+' - This version of ADxRay is outdated. Please access https://github.com/ClaudioMerola/ADxRay for the lastest version and corrections.') -ForegroundColor Red
            }
    }
elseif ($null -eq $VerValid ) 
    {
        Write-Host ('Version: '+$Ver+' - ADxRay version validation was not possible. Please access https://github.com/ClaudioMerola/ADxRay for the lastest version and corrections.') -ForegroundColor Red
    }


######################################### CLOSING #############################################



Add-Content $report "<script type='text/javascript'>"
Add-Content $report "function openTab(pageName) {"
Add-Content $report "var c, tabcontent, tablink;"
Add-Content $report "tabcontent = document.getElementsByClassName('tabcontent');"
Add-Content $report "for (c = 0; c < tabcontent.length; c++) {"
Add-Content $report "tabcontent[c].style.display = 'none';"
Add-Content $report "}"
Add-Content $report "document.getElementById(pageName).style.display = 'block';"
Add-Content $report "}"
Add-Content $report "document.getElementById('OpenFirst').click();"
Add-Content $report "</script>"
Add-Content $report "</body>" 
Add-Content $report "</html>" 


}



########################################################################################################## END OF FUNCTIONS ################################################################################################




############################# RUNNING FUNCTIONS ##########################################



if($Global:Option -eq 1 -or $Global:Option -eq 2 -or $Global:Option -eq 3)
    {
        Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting Forest Pre Inventory")
        $Global:Forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()
        Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting Domains Pre Inventory")
        $Global:Domains = $Global:Forest.domains
        $Global:DomainNames = $Global:Domains.name
        Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting Domain Controllers Pre Inventory")
        $Global:DCs = $Global:Forest.domains | ForEach-Object {$_.DomainControllers}

        Hammer

        $Global:DCs = $Global:DCs.Name

        Start-Sleep 10
        Report
    }
elseif($Global:Option -eq 4)
    {
        Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting Forest Pre Inventory")
        $Global:Forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()
        Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting Domains Pre Inventory")
        $Global:Domains = $Global:Forest.domains
        $Global:DomainNames = $Global:Domains.name
        Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Info - Starting Domain Controllers Pre Inventory")
        $Global:DCs = $Global:Forest.domains | ForEach-Object {$_.DomainControllers}

        Hammer

        Compress-Archive -Path 'C:\ADxRay\Hammer' -DestinationPath 'C:\ADxRay\ADxRay.zip'

    }
elseif($Global:Option -eq 5)
    {
        $Fore = Import-Clixml -Path C:\ADxRay\Hammer\Forest.xml
        $Global:Forest = $Fore.ForestName
        $Global:DomainNames = $Fore.Domains        
        $DomainControllers = Get-ChildItem -Path 'C:\ADxRay\Hammer\' -Recurse
        $DomainControllers = $DomainControllers | Where-Object {$_.Name -like 'inv_*'}
        $Global:DCs = @()
        foreach($DC in $DomainControllers)
            {
                $Global:DCs += $DC.Name.replace('Inv_','').replace('.xml','')
            }
        Report
    }



######################################### ADDING TIME MEASURE #############################################

}
$Measure = $Runtime.Totalminutes.ToString('#######.##')

$index = Get-Content $report

$Index[44] = "<TABLE BORDER=0 WIDTH=20% align='right'><tr><td align='right'><font face='verdana' color='#000000' size='4'> Execution: $Measure Minutes<HR></font></td></tr></TABLE>"

$index | out-file $report

if($Global:Option -eq 1 -or $Global:Option -eq 2 -or $Global:Option -eq 3 -or $Global:Option -eq 5)
    {
        Write-Host ('Report Complete. Report saved at: ') -NoNewline
        write-host $report -ForegroundColor Green -BackgroundColor Red
        Start-Sleep 5
        Invoke-Item $report
    }
elseif($Global:Option -eq 4)
    {
        write-host 'Inventory Complete. Collected files at: ' -NoNewline
        write-host 'C:\ADxRay\ADxRay.zip' -BackgroundColor Red
    }






