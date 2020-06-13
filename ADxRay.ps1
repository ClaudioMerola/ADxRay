######################################################################################################################################################################################
#                                                                                                                                                                                    #
#                                                                                                                                                                                    #
#                                                                         Created by: Claudio Merola                                                                                 #
#                                                                                                                                                                                    #
# This Script is based and inspired on Sukhija Vika's 'Active Directory Health Check' script (https://gallery.technet.microsoft.com/scriptcenter/Active-Directory-Health-709336cd),  #
# the amazing Clint Huffman's 'Performance Analysis of Logs (PAL) tool' (https://github.com/clinthuffman/PAL) and Microsoft's Ned Pyle blogpost 'What does DCDIAG actually… do?'     #
# https://blogs.technet.microsoft.com/askds/2011/03/22/what-does-dcdiag-actually-do/                                                                                                 #
#                                                                                                                                                                                    #
#                                                                                                                                                                                    #
#                                                                                                                                                                                    #
#                                                                                                                                                                                    #                                             
######################################################################################################################################################################################

write-host 'Starting ADxRay Script..'

# Version
$Ver = '3.0'

$SupBuilds = '10.0 (18362)','10.0 (18363)','10.0 (19041)'

$Runtime = Measure-Command -Expression {

$report = ("C:\ADxRay\ADxRay_Report_"+(get-date -Format 'yyyy-MM-dd')+".htm") 
if ((test-path $report) -eq $false) {new-item $report -Type file -Force}
Clear-Content $report 

$ADxRayLog = "C:\ADxRay\ADxRay.log"
if ((test-path $ADxRayLog) -eq $false) {new-item $ADxRayLog -Type file -Force}
Clear-Content $ADxRayLog 

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting ADxRay Script")
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Data Catcher")
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Setting Error Action Preference")

$ErrorActionPreference = "silentlycontinue"

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Forest Pre Inventory")

$Forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Domain Controllers Pre Inventory")

$DCs = $Forest.domains | ForEach-Object {$_.DomainControllers}

if ((Test-Path -Path C:\ADxRay -PathType Container) -eq $false) {New-Item -Type Directory -Force -Path C:\ADxRay}





########################################################################################################## BEGIN OF FUNCTIONS ################################################################################################


###################################### HAMMER FUNCTION ##########################################

function Hammer {

write-host 'Starting The Hammer..'

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting The Hammer!")

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Creating Hammer Folder")

if ((Test-Path -Path C:\ADxRay\Hammer -PathType Container) -eq $false) {New-Item -Type Directory -Force -Path C:\ADxRay\Hammer}

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Killing current running Powershell job")

Get-Job | Remove-Job

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Calling DCDiag")

write-host 'Triggering Forest Inventory..'

start-job -Name 'Diag' -scriptblock {dcdiag /e /s:$($args)} -ArgumentList $Forest.SchemaRoleOwner.Name | Out-Null

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Active Directory RecycleBin Check")

start-job -Name 'RecycleBin' -ScriptBlock {if ((Get-ADOptionalFeature -Filter * | Where {$_.Name -eq 'Recycle Bin Feature' -and $_.EnabledScopes -ne '' })) {'Enabled'}else{'Not Enabled'}} | Out-Null

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Duplicated SPNs check")

start-job -Name 'SPN' -scriptblock {setspn -X -F} | Out-Null

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Trusts Inventory")

start-job -Name 'Trusts' -scriptblock {Get-ADtrust -Filter * -Server $($args) -ErrorAction SilentlyContinue -WarningAction SilentlyContinue } -ArgumentList $Forest.SchemaRoleOwner.Name | Out-Null

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Domain Inventory")

write-host 'Triggering Domain Inventory..'

Foreach ($zone in $Forest.ApplicationPartitions.Name)
    {
    start-job -Name ('Zone_'+$zone) -scriptblock {Get-ADObject -Filter {Name -like '*..InProgress*'} -SearchBase $($args)} -ArgumentList $zone
    }

Foreach ($Domain in $Forest.Domains)
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

    start-job -Name ($Domain.name+'_UsrPWDNeverExpires') -scriptblock {(dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))" -s $($args)).Count} -ArgumentList $Domain.PdcRoleOwner.Name | Out-Null

    start-job -Name ($Domain.name+'_UsrTotal') -scriptblock {(dsquery * -filter sAMAccountType=805306368 -s $($args) -attr samAccountName -attrsonly -limit 0).Count} -ArgumentList $Domain.PdcRoleOwner.Name  | Out-Null

    start-job -Name ($Domain.name+'_UsrEnable') -scriptblock {(dsquery user -s $($args) -limit 0).Count} -ArgumentList $Domain.PdcRoleOwner.Name  | Out-Null

    start-job -Name ($Domain.name+'_UsrDisable') -scriptblock {(dsquery user -disabled -s $($args) -limit 0).Count} -ArgumentList $Domain.PdcRoleOwner.Name  | Out-Null

    start-job -Name ($Domain.name+'_UsrInactive') -scriptblock {(dsquery user -inactive 12 -s $($args) -limit 0).Count} -ArgumentList $Domain.PdcRoleOwner.Name  | Out-Null

    start-job -Name ($Domain.name+'_Comps') -scriptblock {dsquery * -filter sAMAccountType=805306369 -s $($args) -Attr OperatingSystem  -limit 0} -ArgumentList $Domain.PdcRoleOwner.Name  | Out-Null

    start-job -Name ($Domain.name+'_GrpDomAdmins') -scriptblock {(dsquery * -filter '(&(objectclass=group)(sAMAccountName=Domain Admins))' -s $($args) -Attr member -limit 0)} -ArgumentList $Domain.PdcRoleOwner.Name  | Out-Null

    start-job -Name ($Domain.name+'_GrpSchemAdmins') -scriptblock {(dsquery * -filter '(&(objectclass=group)(sAMAccountName=Schema Admins))' -s $($args) -Attr member -limit 0)} -ArgumentList $Domain.PdcRoleOwner.Name  | Out-Null

    start-job -Name ($Domain.name+'_GrpEntAdmins') -scriptblock {(dsquery * -filter '(&(objectclass=group)(sAMAccountName=Enterprise Admins))' -s $($args) -Attr member -limit 0)} -ArgumentList $Domain.PdcRoleOwner.Name  | Out-Null

    start-job -Name ($Domain.name+'_GrpSrvOpers') -scriptblock {(dsquery * -filter '(&(objectclass=group)(sAMAccountName=Server Operators))' -s $($args) -Attr member -limit 0)} -ArgumentList $Domain.PdcRoleOwner.Name  | Out-Null

    start-job -Name ($Domain.name+'_GrpDNSServ') -scriptblock {(dsquery * -filter '(&(objectclass=group)(sAMAccountName=DnsAdmins))' -s $($args) -Attr member -limit 0)} -ArgumentList $Domain.PdcRoleOwner.Name | Out-Null

    start-job -Name ($Domain.name+'_GrpAdms') -scriptblock {(dsquery * -filter '(&(objectclass=group)(sAMAccountName=Administrators))' -s $($args) -Attr member -limit 0)} -ArgumentList $Domain.PdcRoleOwner.Name  | Out-Null

    start-job -Name ($Domain.name+'_GrpAll') -scriptblock {dsquery * -filter objectclass=group -s $($args) -Attr member -limit 0} -ArgumentList $Domain.PdcRoleOwner.Name  | Out-Null

}

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Domain Controllers Inventory")

Write-Host ('Triggering the Inventory of: ') -NoNewline
write-host $DCs.Count -NoNewline -ForegroundColor Magenta
Write-Host ' Domain Controllers..'

Foreach ($DC in $DCs) {

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Domain Controllers Basic Inventory on: "+$DC.Name)

    start-job -Name ($DC.Name+'_Infos') -scriptblock {Get-ADDomainController -Server $($args[0]) -ErrorAction SilentlyContinue -WarningAction SilentlyContinue} -ArgumentList $DC.Name | Out-Null

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Domain Controllers Events Inventory on: "+$DC.Name)

    start-job -Name ($DC.Name+'_EvtSystem') -scriptblock {Get-EventLog -List -ComputerName $args | where {$_.Log -eq 'System'}} -ArgumentList $DC.Name | Out-Null

    start-job -Name ($DC.Name+'_x64Softwares') -scriptblock {Invoke-Command -cn $($args[0]) -ScriptBlock {Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*}} -ArgumentList $DC.Name | Out-Null

    start-job -Name ($DC.Name+'_x86Softwares') -scriptblock {Invoke-Command -cn $($args[0]) -ScriptBlock {Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*}} -ArgumentList $DC.Name | Out-Null

    start-job -Name ($DC.Name+'_Features') -scriptblock {Get-WindowsFeature -ComputerName $($args[0]) | where {$_.Installed -eq 'Installed'}} -ArgumentList $DC.Name | Out-Null
    
    start-job -Name ($DC.Name+'_EvtSecurity') -scriptblock {Get-EventLog -List -ComputerName $args | where {$_.Log -eq 'Security'}} -ArgumentList $DC.Name | Out-Null
   
    start-job -Name ($DC.Name+'_Evts') -scriptblock {(Get-EventLog -ComputerName $args -LogName Security -InstanceId 4618,4649,4719,4765,4766,4794,4897,4964,5124,1102).Count} -ArgumentList $DC.Name | Out-Null

    start-job -Name ($DC.Name+'_BatchJobEvt') -scriptblock {(Get-EventLog -LogName Security -InstanceId 4624 -Message '*Logon Type:			4*' -ComputerName $args).Count} -ArgumentList $DC.Name | Out-Null

    start-job -Name ($DC.Name+'_CleartxtEvt') -scriptblock {(Get-EventLog -LogName Security -InstanceId 4624 -Message '*Logon Type:			8*' -ComputerName $args).Count} -ArgumentList $DC.Name | Out-Null
    
    start-job -Name ($DC.Name+'_HotFix') -scriptblock {Get-HotFix -ComputerName $args | sort HotFixID,{ [datetime]$_.InstalledOn } -desc | group HotFixID | % { $_.group[0] }} -ArgumentList $DC.Name | Out-Null

    start-job -Name ($DC.Name+'_GPResult') -scriptblock {Get-GPResultantSetOfPolicy -ReportType Xml -Path ("C:\ADxRay\Hammer\RSOP_"+$args+".xml")} -ArgumentList $DC.Name | Out-Null

    start-job -Name ($DC.Name+'_DNS') -scriptblock {Get-DnsServer -ComputerName $args -ErrorAction SilentlyContinue -WarningAction SilentlyContinue} -ArgumentList $DC.Name | Out-Null

    start-job -Name ($DC.Name+'_ldapRR') -scriptblock {Get-DnsServerResourceRecord -ZoneName ('_msdcs.'+$($args[0])) -Name '_ldap._tcp.dc' -ComputerName $($args[1]) -ErrorAction SilentlyContinue -WarningAction SilentlyContinue} -ArgumentList $DC.Domain,$DC.Name | Out-Null

}

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Waiting Inventories Conclusion")

$c = 0
while (get-job | ? {$_.State -eq 'Running'})
{
$c = (((((get-job).count - (get-job | ? {$_.State -eq 'Running'}).Count)) / (get-job).Count) * 100)
$c = [math]::Round($c)
Write-Progress -activity 'Running Inventory'  -Status "$c% Complete." -PercentComplete $c
}
Write-Progress -activity 'Running Inventory' -Status "100% Complete." -Completed

Get-Job | Wait-Job | Out-Null

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - All Inventories are not completed")

write-host 'Inventories done..'

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting to Process the Inventories")

write-host 'Starting to Process the Results..'

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting to Process Forest Inventory")

$DuplicatedZones = @()
$Diag = Receive-Job -Name 'Diag' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
$RecycleBin = Receive-Job -Name 'RecycleBin' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
$SPN = Receive-Job -Name 'SPN' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
$Trusts = Receive-Job -Name 'Trusts' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
Foreach ($zone in $Forest.ApplicationPartitions.Name){
$DuplicatedZones += receive-job -Name ('Zone_'+$zone) 
}

if ((test-path 'C:\ADxRay\Hammer\Forest.xml') -eq $true) {remove-item -Path 'C:\ADxRay\Hammer\Forest.xml' -Force}

$Fores = @{

'ForestName' = $Forest.Name;
'Domains' = $Forest.Domains.Name;
'RecycleBin' = $RecycleBin;
'ForestMode' = $Forest.ForestMode;
'GlobalCatalogs' = $Forest.GlobalCatalogs.Name;
'Sites' = $Forest.Sites.Name;
'Trusts' = $Trusts.name;
'SPN' = ($SPN | Select-String -Pattern ('group of duplicate SPNs')).ToString();
'DuplicatedDNSZones' = $DuplicatedZones.DistinguishedName

}

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Registering Forest XML File")

$Fores | Export-Clixml -Path 'C:\ADxRay\Hammer\Forest.xml'

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting to Process Trust Inventory")

Foreach ($Trust in $Trusts)
{

if ((test-path ('C:\ADxRay\Hammer\Trust_'+$Trust.Name+'.xml')) -eq $true) {remove-item -Path ('C:\ADxRay\Hammer\Trust_'+$Trust.Name+'.xml') -Force}

$Trus = @{
'ForestName' = $Forest.Name;
'Name' = $Trust.Name;
'Source' = $Trust.Source;
'Target' = $Trust.Target;
'Direction' = $Trust.Direction;
'ForestTransitive' = $Trust.ForestTransitive;
'IntraForest' = $Trust.IntraForest;
'SIDFilteringForestAware' = $Trust.SIDFilteringForestAware

        }

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Registering Trust XML File for: "+$Trust)

$Trus | Export-Clixml -Path ('C:\ADxRay\Hammer\Trust_'+$Trust.Name+'.xml')

}

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting to Process Domain Inventory")

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting to Process Domains Details")


Foreach ($Domain in $Forest.Domains)
    {

if ((test-path ('C:\ADxRay\Hammer\Domain_'+$Domain+'.xml')) -eq $true) {remove-item -Path ('C:\ADxRay\Hammer\Domain_'+$Domain.Name+'.xml') -Force}

    $InvDom = Receive-Job -Name ($Domain.Name+'_Inv') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    $SysVolDom = Receive-Job -Name ($Domain.Name+'_SysVol') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    $UsrPWDNeverExpires = Receive-Job -Name ($Domain.Name+'_UsrPWDNeverExpires') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    $UsrTotal = Receive-Job -Name ($Domain.name+'_UsrTotal') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    $UsrEnable = Receive-Job -Name ($Domain.name+'_UsrEnable') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    $UsrDisable = Receive-Job -Name ($Domain.name+'_UsrDisable') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    $UsrInactive = Receive-Job -Name ($Domain.name+'_UsrInactive') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    $Comps = Receive-Job -Name ($Domain.name+'_Comps') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    $GrpDomAdmins = Receive-Job -Name ($Domain.name+'_GrpDomAdmins') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    $GrpSchemaAdmins = Receive-Job -Name ($Domain.name+'_GrpSchemAdmins') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    $GrpEntAdmins = Receive-Job -Name ($Domain.name+'_GrpEntAdmins') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    $GrpSrvOpers = Receive-Job -Name ($Domain.name+'_GrpSrvOpers') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    $GrpDNSServ = Receive-Job -Name ($Domain.name+'_GrpDNSServ') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    $GrpAdms = Receive-Job -Name ($Domain.name+'_GrpAdms') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    $GrpAll = Receive-Job -Name ($Domain.name+'_GrpAll') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    $GPOALL = Receive-Job -Name ($Domain.name+'_GPOAll') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

$DomainTable = @{

'Domain' = $Domain.name;
'DNSRoot' = $InvDom.DNSRoot;
'ParentDomain' = $InvDom.ParentDomain;
'ChildDomains' = $InvDom.ChildDomains;
'DomainMode' = $InvDom.DomainMode;
'ComputersContainer' = $InvDom.ComputersContainer;
'UsersContainer' = $InvDom.UsersContainer;
'DCCount' = ($Forest.domains | where {$_.Name -eq $InvDom.DNSRoot}).DomainControllers.Count;
'SysVolContent' = $SysVolDom;
'USR_PasswordNeverExpires' = $UsrPWDNeverExpires;
'USR_Totalusers' = $UsrTotal;
'USR_EnabledUsers' = $UsrEnable;
'USR_DisableUsers' = $UsrDisable;
'USR_InactiveUsers' = $UsrInactive;
'Computers' = $Comps;
'Domain Admins'=$GrpDomAdmins;
'Schema Admins'=$GrpSchemaAdmins;
'Enterprise Admins'=$GrpEntAdmins;
'Server Operators'=$GrpSrvOpers;
'DnsAdmins'=$GrpDNSServ;
'Administrators'=$GrpAdms;
'All'=$GrpAll

}

$DomainTable | Export-Clixml -Path ('C:\ADxRay\Hammer\Domain_'+$Domain.Name+'.xml')

}


Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting to Process Domain Controllers Inventory")

Foreach ($DC in $DCs) {

if ((test-path ("C:\ADxRay\Hammer\Inv_"+$DC.Name+".xml")) -eq $true) {remove-item -Path ("C:\ADxRay\Hammer\Inv_"+$DC.Name+".xml") -Force}

$DC0 = Receive-Job -Name ($DC.Name+'_Infos') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
$EvtSys = Receive-Job -Name ($DC.Name+'_EvtSystem') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
$EvtSec = Receive-Job -Name ($DC.Name+'_EvtSecurity') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
$Evts = Receive-Job -Name ($DC.Name+'_Evts') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
$BatEvts = Receive-Job -Name ($DC.Name+'_BatchJobEvt') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
$CleEvts = Receive-Job -Name ($DC.Name+'_CleartxtEvt') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
$HotFix = Receive-Job -Name ($DC.Name+'_HotFix') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
$DNS = Receive-Job -Name ($DC.Name+'_DNS') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
$LdapRR = Receive-Job -Name ($DC.Name+'_ldapRR') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
$Features = Receive-Job -Name ($DC.Name+'_Features') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
$SWx64 = Receive-Job -Name ($DC.Name+'_x64Softwares') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
$SWx86 = Receive-Job -Name ($DC.Name+'_x86Softwares') -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

$DomControl = @{

    'Domain' = $DC0.Domain;
    'Hostname' = $DC0.Hostname;
    'IsReadOnly' = $DC0.IsReadOnly;
    'IPv4Address' = $DC0.IPv4Address;
    'IsGlobalCatalog' = $DC0.IsGlobalCatalog;
    'OperatingSystem' = $DC0.OperatingSystem;
    'OperatingSystemVersion' = $DC0.OperatingSystemVersion;
    'OperationMasterRoles' = $DC0.OperationMasterRoles;
    'Site' = $DC0.Site;
    'CriticalEvts' = $Evts;
    'DCSysLog' = $EvtSys.MaximumKilobytes;
    'DCSecLog' = $EvtSec.MaximumKilobytes;
    'DCBatEvts' = $BatEvts;
    'DCCleEvts' = $CleEvts;
    'HotFix' = $HotFix;
    'DNS' = $DNS;
    'ldapRR' = $LdapRR;
    'DCDiag' = $Diag | Select-String -Pattern ($DC.Name.Split('.')[0]);
    'InstalledFeatures' = $Features.Name;
    'InstalledSoftwaresx64' = $SWx64 | ? {$_.DisplayName} | Select-Object DisplayName, DisplayVersion, Publisher
    'InstalledSoftwaresx86' = $SWx86 | ? {$_.DisplayName} | Select-Object DisplayName, DisplayVersion, Publisher

}

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Registering Domain Controller XML file for: "+$DC)

$DomControl | Export-Clixml -Path ('C:\ADxRay\Hammer\Inv_'+$DC.Name+'.xml')

}

$jbs = Get-Job

foreach ($JB in $jbs){
if ($JB.State -eq 'Failed') 
{
$JbName = $jb.Name 
$jbcmd = $jb.command
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - The following Inventory Job Failed: "+$jbName)
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - With the following Command Line: "+$jbcmd)
}
}

Write-Host ('End of Hammer phase. ') -NoNewline
write-host ($jbs | ? {$_.State -eq 'Completed'}).Count -NoNewline -ForegroundColor Magenta
Write-Host ' Inventory jobs completed and ' -NoNewline
write-host ($jbs | ? {$_.State -eq 'Failed'}).Count -NoNewline -ForegroundColor Red
Write-Host ' Inventory jobs failed..'

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - End of Hammer")

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
<button class="tablink" onclick="openTab('Softwares')">Softwares</button>
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

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Forest Report: "+$Forest)

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



Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - RecycleBin status: "+$RecycleBin)

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - End of Forest Reporting phase.")


}
Catch { 
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors found -------------")
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - The following error ocurred during catcher: "+$_.Exception.Message)
}

Add-content $report  "</table>"


add-content $report "<BR><BR><BR>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Be sure to investigate and solve any issues reported here, also is important to remember to enable every feature available. Those features were developed by the Microsoft team to help you troubleshoot and manage the environment.</td></tr></TABLE>" 

add-content $report "<BR><BR><BR><BR>"





######################################### TRUST #############################################

write-host 'Starting Trust Analysis..'

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Trust reporting")

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

        $Trust1 = Import-Clixml -Path ('C:\ADxRay\Hammer\Trust_'+$Trusts+'.xml')

        $T3Source = $Trust1.Source
        $T3Target = $Trust1.Target
        $T3Dir = $Trust1.Direction
        $T3Trans = $Trust1.ForestTransitive
        $T3Intra = $Trust1.IntraForest
        $T3SIDFil = $Trust1.SIDFilteringForestAware

        Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Trust Found for: "+$T3Source+ " To "+$T3Target)
    
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
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - The following error ocurred during catcher: "+$_.Exception.Message)
}
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - End of TRUST Report phase.")

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

write-host 'Starting Domains Reporting..'

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Domains Reporting")


add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>Active Directory Domains View ($Forest)</h3>" 
add-content $report  "</CENTER>"
add-content $report "<BR>"

Try{

Add-Content $report "</tr>" 

Foreach ($Domain0 in $Fore.Domains)
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

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Reporting the following domain: "+$D2Name)

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
Add-Content $report  "<th bgcolor='WhiteSmoke' font='tahoma'><B>Forest Namey</B></th>" 
    Add-Content $report "<td bgcolor='White' align=center>$ForeName</td>" 
Add-Content $report "</tr>"     
Add-Content $report "<tr>" 
Add-Content $report  "<th bgcolor='WhiteSmoke' font='tahoma'><B>Domain Namey</B></th>" 
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
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - The following error ocurred during catcher: "+$_.Exception.Message)
}
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - End of Domain phase.")

Add-content $report  "</table>"

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Domain's design must be as clear as possible and always based on best practices. Remember to consult <a href='https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/creating-a-site-design'>Creating a Site Design</a> and <a href='https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/determining-the-number-of-domains-required'>Determining the Number of Domains Required</a> before adding any new Domains in the topology.</td></tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR><BR><BR><BR><BR><BR>"


######################################### SYSVOL #############################################

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting SysVol Reporting")

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

Foreach ($Domain in $Fore.domains) 
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
                Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - "+$SYSEXT+" extension found, total of: "+$SYSCOUNT+" files ("+$SYSSIZE+")")
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

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - End of SYSVol Reporting")

Add-content $report  "</table>"

add-content $report "</CENTER>"

add-content $report "<BR><BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Sysvol folder contain the Group Policies physical files and scripts used in the Group Policy Objects, those folders are replicated between Domain Controllers from time to time, is very important to only keep essential files in Sysvol as so as to keep the folder's size at the very minimum.</td></tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR><BR><BR><BR><BR><BR>"


######################################### USERS #############################################

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting User Accounts Reporting")


add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>User Accounts</h3>" 
add-content $report  "</CENTER>"
add-content $report "<BR>"

add-content $report  "<table width='60%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='15%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Total Users</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Enabled Users</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Disabled Users</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Inactive Users</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Password Never Expires</B></td>" 

Add-Content $report "</tr>" 

Foreach ($Domain in $Fore.domains) 
    {
        Try{
        $UsDomain = $Domain

        $Usrs = Import-Clixml -Path ('C:\ADxRay\Hammer\Domain_'+$Domain+'.xml')

        $AllUsers = $Usrs.USR_Totalusers

        $UsersDisabled = $Usrs.USR_DisableUsers
        $UsersEnabled = $Usrs.USR_EnabledUsers
        $UsersInactive = $Usrs.USR_InactiveUsers
        $UsersPWDNeverExpire = $usrs.USR_PasswordNeverExpires


        Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Inventoring User Accounts in the Domain: "+$UsDomain)
        Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Total users found: "+$AllUsers)

        Add-Content $report "<tr>" 

        Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
        Add-Content $report "<td bgcolor='White' align=center>$AllUsers</td>"         
        Add-Content $report "<td bgcolor='White' align=center>$UsersEnabled</td>"               
        Add-Content $report "<td bgcolor='White' align=center>$UsersDisabled</td>"    
        if ($UsersInactive -eq '' -or $UsersInactive -eq 0) 
            {
                Add-Content $report "<td bgcolor= 'Lime' align=center>0</td>"
            }
        else 
            { 
                Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$UsersInactive</font></td>" 
            }
        if ($UsersPWDNeverExpire -eq '' -or $UsersPWDNeverExpire -eq 0) 
            {
                Add-Content $report "<td bgcolor= 'Lime' align=center>0</td>"
            }
        else 
            { 
                Add-Content $report "<td bgcolor= 'Yellow' align=center>$UsersPWDNeverExpire</td>" 
            }

    Add-Content $report "</tr>"
    }
Catch { 
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors were found during the User Accounts Inventoring -------------")
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - The following error ocurred during catcher: "+$_.Exception.Message)
}
    }


Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - User Accounts Reporting finished")

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - End of User Account phase.")
 
Add-content $report  "</table>" 

add-content $report "<BR><BR>"

add-content $report "<TABLE BORDER=0 WIDTH=95%><tr><td>This overview state of user accounts will present the <B>Total number of users</b>, as so as the total number of <B>Disabled User Accounts</B>, <B>Inactive User Accounts </B> and User Accounts that have the <B>'Password Never Expires'</B> option set. Most of those counters should be <B>0</B> or the smallest as possible. Exceptions may apply, but should not be a common practice.</td></tr></TABLE>" 

add-content $report "</CENTER>"

Write-Host ('User Account Reporting Done. Found: ') -NoNewline
write-host $AllUsers -NoNewline -ForegroundColor Magenta
Write-Host ' User Accounts'

add-content $report "<BR><BR><BR><BR>"



######################################### COMPUTER ACCOUNTS #############################################

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Computer Accounts reporting")


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

Foreach ($Domain in $Fore.domains) 
    {

    Try{

    Add-Content $report "<tr>" 

    $PC =  Import-Clixml -Path ('C:\ADxRay\Hammer\Domain_'+$Domain+'.xml')

    $PCAll = $PC.Computers
    $PCAll =[System.Collections.ArrayList]$PCAll
    $PCAll.RemoveAt(0)

    $PCAllC = $PCAll.Count
    $PCServer = ($PCAll | where {$_ -like '* Server*'}).Count
    $PCWS = ($PCAll | where {$_ -notlike '* Server*'}).Count
    $PCServerUnsupp = ($PCAll | where {$_ -like '* Server*'} | Where {$_ -like '* NT*' -or $_ -like '*2000*' -or $_ -like '*2003*' -or $_ -like '*2008*'}).Count
    $PCWSUnsupp = ($PCAll | where {$_ -notlike '* Server*'} | Where {$_ -like '* NT*' -or $_ -like '*2000*' -or $_ -like '* 95*' -or $_ -like '* 7*' -or $_ -like '* 8 *'  -or $_ -like '* 98*' -or $_ -like '*XP*' -or $_ -like '* Vista*'}).Count


    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Reporting Computer Accounts in the Domain: "+$Domain)
    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Total Computers found: "+$PCAllC)


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
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors were found during the Computer Accounts Inventoring -------------")
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - The following error ocurred during catcher: "+$_.Exception.Message)
}
    }

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Computer Accounts Reporting finished")

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - End of Computer Account phase.")

Add-content $report  "</table>" 

add-content $report "<BR><BR>"

add-content $report "<TABLE BORDER=0 WIDTH=95%><tr><td>Those counters present a list of total Windows Servers and Workstations, and the total number of Windows Servers and Workstations that are enabled (and possibly active in the environment) but are running unsupported versions of Windows. To verify which versions of Windows are out of support, verify: <a href='https://docs.microsoft.com/en-us/lifecycle/overview/product-end-of-support-overview>Overview - Product end of support</a>, <a href='https://support.microsoft.com/en-us/help/13853/windows-lifecycle-fact-sheet'>Windows lifecycle fact sheet</a> and <a href='https://support.microsoft.com/en-us/help/10736/windows-what-does-it-mean-if-not-supported'>What does it mean if Windows isn't supported?</a>.</td></tr></TABLE>"  

add-content $report "</CENTER>"

Write-Host ('Computer Account Reporting Done. Found: ') -NoNewline
write-host $PCAllC -NoNewline -ForegroundColor Magenta
Write-Host ' Computer Accounts'

add-content $report "<BR><BR><BR><BR><BR><BR>"


######################################### GROUPS #############################################

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Groups Reporting")

add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>Active Directory Admin Groups</h3>" 
add-content $report  "</CENTER>"
add-content $report "<BR>"
 
add-content $report  "<table width='60%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='15%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='15%' align='center'><B>Group Name</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>Members</B></td>" 

Add-Content $report "</tr>" 

$Groups = @('Domain Admins','Schema Admins','Enterprise Admins','Server Operators','DnsAdmins','Administrators')

Foreach ($Domain in $Fore.domains) 
    {

    Try{

    $Grp =  Import-Clixml -Path ('C:\ADxRay\Hammer\Domain_'+$Domain+'.xml')

        Foreach ($gp in $Groups)
            {
            $GpTemp = 0
            $GpTemp = $Grp.($gp)

            $GCounter = (($GpTemp -split(';') | where {$_ -like '*DC*'})).Count 

                    $GName = $gp
                    Add-Content $report "<tr>"
                    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
                    Add-Content $report "<td bgcolor='White' align=center>$GName</td>" 

                    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Inventoring Group: "+$GName)
                    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Total members found: "+$GCounter)

                    if ($GCounter -ge 2) 
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
        Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors were found during the Domain Groups Reporting -------------")
        Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - The following error ocurred during catcher: "+$_.Exception.Message)
                }
    }

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Domain Groups Inventory finished")


Add-content $report  "</table>"

add-content $report "<BR><BR>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Having too many users with more than necessary permissions may result in serious security breaches. Microsoft recommends the group Schema Admins should remain empty until there is a real need to change the environment´s schema, and any member should be removed after that change. Make sure that only the very necessary user accounts are present in those groups, unauthorized users may cause big damage. And remember to review the <a href='https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory'>Best Practices for Securing Active Directory</a>. And specially '<a href='https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models'>Implementing Least-Privilege Administrative Models</a>'. </td></tr></TABLE>" 

add-content $report "</CENTER>"

add-content $report "<BR><BR><BR><BR>"



######################################### EMPTY GROUPS #############################################

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Empty Groups Reporting")


add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>Active Directory General Groups</h3>" 
add-content $report  "</CENTER>"
add-content $report "<BR>"
 
add-content $report  "<table width='60%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>Groups</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>Large Groups</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>Empty Groups</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>Average Members</B></td>" 
 

Add-Content $report "</tr>" 

Foreach ($Domain in $Fore.domains)
    {

    Try{

    $Grp =  Import-Clixml -Path ('C:\ADxRay\Hammer\Domain_'+$Domain+'.xml')

    $GroupsMembers = @()

    $GroupAll = $Grp.All
    $Counter = @()
            Foreach ($gp in $GroupAll)
            {
                $Counter += (($gp -split(';') | where {$_ -like '*DC*'})).Count 
            }


        $GroupTotal = $Counter.Count
        $GroupLarge = ($Counter | where {$_ -ge 50}).Count
        $GroupEmpty = ($Counter | where {$_ -eq 0}).Count
        $GroupAve = ($Counter | Measure-Object -Average).Average
        
        Add-Content $report "<tr>" 

        Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
        Add-Content $report "<td bgcolor='White' align=center>$GroupTotal</td>" 

        Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Reporting Empty Groups in the Domain: "+$Domain)
        Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Total Empty Groups found: "+$GroupEmpty)
        if ($GroupLarge -gt 30) 
            {
                Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GroupLarge</font></td>"
            }
        else 
            {
                Add-Content $report "<td bgcolor= 'Lime' align=center> $GroupLarge</td>" 
            }
        if ($GroupEmpty -gt 20) 
            {
                Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GroupEmpty</font></td>"
            }
        else 
            {
                Add-Content $report "<td bgcolor= 'Lime' align=center>$GroupEmpty</td>" 
            }
        if ($GroupAve -ge 1.00 -and $GroupAve -lt 3.00) 
            {
                $GroupAve = $GroupAve.tostring("#.##")
                Add-Content $report "<td bgcolor= 'Yellow' align=center>$GroupAve</td>"
            }
        elseif ($GroupAve -ge 0.00 -and $GroupAve -lt 1.00) 
            {
                $GroupAve = $GroupAve.tostring("#.##")
                Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GroupAve</font></td>"
            }
        else 
            {
                $GroupAve = $GroupAve.tostring("#.##") 
                Add-Content $report "<td bgcolor='Lime' align=center>$GroupAve</td>" 
            }


        Add-Content $report "<tr>"
        }
Catch { 
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors were found during the Empty Domain Groups Inventoring -------------")
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - The following error ocurred during catcher: "+$_.Exception.Message)
}
    }

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Empty Domain Groups Inventory finished")

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - End of Groups phase.")

Add-content $report  "</table>"

add-content $report "<BR><BR>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Having a fair number of groups is not just a good practice, it's vital to ensure an easier and 'clean' management of Active Directory, usually don't make sense have more groups than users or even groups with only few users. And remember to review the <a href='https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory'>Best Practices for Securing Active Directory</a>. And specially '<a href='https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models'>Implementing Least-Privilege Administrative Models</a>'. </td></tr></TABLE>" 

add-content $report "</CENTER>"

Write-Host ('AD Groups Reporting Done. Found: ') -NoNewline
write-host $GroupTotal -NoNewline -ForegroundColor Magenta
Write-Host ' Groups'

add-content $report "<BR><BR><BR><BR><BR><BR>"



######################################### GPOs #############################################

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Group Policy Objects Reporting")

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


Foreach ($Domain in $Fore.domains)
    {

    Try{

    [xml]$XmlDocument = Get-Content -Path ('C:\ADxRay\Hammer\GPOs_'+$Domain+'.XML')

    $GPO =  $XmlDocument.report.gpo

    $GpoC = @()
    $GPEmpt = ($Gpo | where {$_.User.VersionDirectory -eq 0 -and $_.User.VersionSysVol -eq 0 -and $_.Computer.VersionDirectory -eq 0 -and $_.Computer.VersionSysVol -eq 0}).Name.Count
    $GPBIG = ($Gpo | Where {(([int]$_.User.VersionDirectory) + ([int]$_.Computer.VersionDirectory)) -ge 1000}).Name.Count
    $GPOAll = $GroupPolicy.report.GPO.Count
    $GPOWithouLink = ($GPO  | where {!$_.LinksTo} ).Count
    $GPODisables = ($GPO.LinksTo.Enabled | where {$_ -eq $false}).Count

 Add-Content $report "<tr>"

                Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
                Add-Content $report "<td bgcolor='White' align=center>$GPOAll</td>" 

                Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Inventoring Group Policies in the Domain: "+$Domain)
                Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Total GPOs found: "+$GPOAll)
                if ($GPOWithouLink -ge 1) 
                    {
                        Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GPOWithouLink GPOs</font></td>"
                    }
                else 
                    {
                        Add-Content $report "<td bgcolor= 'Lime' align=center>$GPOWithouLink GPOs</td>" 
                    }
                if ($GPEmpt -ge 1) 
                    {
                        Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GPEmpt GPOs</font></td>"
                    }
                else 
                    {
                        Add-Content $report "<td bgcolor= 'Lime' align=center>$GPEmpt GPOs</td>" 
                    }

                if ($GPODisables -ge 1) 
                    {
                        Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GPODisables GPOs</font></td>"
                    }
                else 
                    {
                        Add-Content $report "<td bgcolor= 'Lime' align=center>$GPODisables GPOs</td>" 
                    }

                if ($GPBIG -ge 1) 
                    {
                        Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GPBIG GPOs</font></td>"
                    }
                else 
                    {
                        Add-Content $report "<td bgcolor= 'Lime' align=center>$GPBIG GPOs</td>" 
                    }

                Add-Content $report "</tr>"
                }
Catch { 
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors were found during the GPOs Inventoring -------------")
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - The following error ocurred during catcher: "+$_.Exception.Message)
}
    }


Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - GPOs Repoorting finished")


Add-content $report  "</table>" 

add-content $report "<BR><BR>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Group Policy represent an important part of Active Directory management (without mention its impact on Servers and Workstation). Make sure GPO conflicts are avoided always as possible, also take GPO backups at a regular basis (<a href='https://docs.microsoft.com/en-us/powershell/module/grouppolicy/backup-gpo?view=win10-ps'>Backup-GPO</a>).</td></tr></TABLE>" 

add-content $report "</CENTER>"

Write-Host ('Found: ') -NoNewline
write-host $GPOall -NoNewline -ForegroundColor Magenta
Write-Host ' GPOs. Starting the Reporting..' 

add-content $report "<BR><BR><BR><BR>"


######################################### GPOs WITHOUT LINK #############################################


Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting GPOs Without Link Reporting")


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


Foreach ($Domain in $Fore.domains) 
    {

    Try{

    [xml]$XmlDocument = Get-Content -Path ('C:\ADxRay\Hammer\GPOs_'+$Domain+'.XML')

    $Gpos = $XmlDocument.report.gpo

    Foreach ($gpo in $gpos)
    {

    $GpoName = $Gpo.Name
    $GpoUserADVer = $Gpo.User.VersionDirectory
    $GpoCompADVer = $Gpo.Computer.VersionDirectory
    $GposNoLink = $GPO | where {!$_.LinksTo}
    $GpoModDate =  $Gpo.ModifiedTime

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Inventoring the Following GPO: "+$GpoName)

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
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - The following error ocurred during catcher: "+$_.Exception.Message)
}

}

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - GPOs without link Inventory finished")

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - End of log file")

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

write-host 'Starting Domain Controller Reporting..'

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Domain Controllers Reporting")

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

foreach ($DC in $DCs)
    {
    Try{
    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Start Reporting of: "+$DC)

    $DCD = Import-Clixml -Path ('C:\ADxRay\Hammer\Inv_'+$DC+'.xml')

    $Domain = $DC.Domain
    $DCHostName = $DC.name
    $DCEnabled = $DCD.IsReadOnly
    $DCIP = $DCD.IPv4Address
    $SMBv1 = $DCD.InstalledFeatures | ? {$_ -contains 'FS-SMB1'}
    $DCGC = $DCD.IsGlobalCatalog
    $DCOS = $DCD.OperatingSystem
    $DCOSD = $DCD.OperatingSystemVersion
    $FSMO = $DCD.OperationMasterRoles
    $Site = $DCD.Site

    Add-Content $report "<tr>"

    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DCHostname</td>" 

    if ($DCEnabled -eq $True)
        {
            Add-Content $report "<td bgcolor='White' align=center>RODC</td>"  
        }
    else
        {
            Add-Content $report "<td bgcolor='White' align=center>Full DC</td>"  
        }

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Reporting IP of: "+$DCHostName)

    Add-Content $report "<td bgcolor='White' align=center>$DCIP</td>" 

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Reporting Global Catalog of: "+$DCHostName)

    if (!$SMBv1)
        {
            Add-Content $report "<td bgcolor='White' align=center>Disable</td>"  
        }
    else
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Enable</font></td>"  
        }

    Add-Content $report "<td bgcolor='White' align=center>$DCGC</td>" 

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Reporting Operating System Version of: "+$DCHostName)
        if ($DCOS -like '* NT*' -or $DCOS -like '* 2000*' -or $DCOS -like '* 2003*')
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$DCOS</font></td>" 
        }
    elseif ($DCOS -like '* 2008*' -or $DCOS -like '* 2012*') 
        {
            Add-Content $report "<td bgcolor= 'Yellow' align=center>$DCOS</td>" 
        }
    elseif ($DCOS -like '* 2016*' -or $DCOS -like '* 2019*') 
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


    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Reporting FSMO of: "+$DCHostName)

    Add-Content $report "<td bgcolor='White' align=center>$FSMO</td>" 

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Reporting Site of: "+$DCHostName)

    Add-Content $report "<td bgcolor='White' align=center>$Site</td>" 
    
    Add-Content $report "</tr>" 

    }
    Catch 
            { 
    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors found -------------")
    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - The following error ocurred during catcher: "+$_.Exception.Message)    
            }
    }


Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Domain Controllers Reporting finished")

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




######################################### DNS Server #############################################

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DNS Server Reporting")

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

        foreach ($DC in $DCs.Name)
            {
                Try{

                remove-variable ldapRR
                remove-variable DNS

                $DCD = Import-Clixml -Path ('C:\ADxRay\Hammer\Inv_'+$DC+'.xml')

                $DNS = $DCD.DNS

                Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Reporting DNS Server: "+$DC)

                $ldapRR = $DCD.ldapRR
                    
                $DNSSRVRR = 'Ok'
                Foreach ($DCOne in $DCs.Name)
                    {
                        if ($DCOne.split('.')[0] -notin $ldapRR.RecordData.DomainName.split('.'))
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
                $DNSZoneScavenge = ($dns.ServerZoneAging | where {$_.AgingEnabled -eq $True }).ToString.Count
                $DNSBindSec = $DNS.ServerSetting.BindSecondaries
                $DNSSca = $DNS.ServerScavenging.ScavengingState
                $DNSRecur = $DNS.ServerRecursion.Enable
                $DNSZoneCount = ($DNS.ServerZone | where {$_.ZoneName -notlike '*.arpa' -and $_.ZoneName -ne 'TrustAnchors'}).Count
                $DNSRootC = $DNSRootHintC.Count


                Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Validating DNS Server: "+$DNSName)

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
            Catch { 
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors were found during the DNS Server Inventoring -------------")
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - The following error ocurred during catcher: "+$_.Exception.Message)
            }
    }


Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - DNS Servers Reporting finished")

Add-content $report  "</table>"

add-content $report "</CENTER>"

add-content $report "<BR><BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>DNS is an important part of Active Directory’s health, so its maintenance is very critical for the safety and functionality of the environment. If you did not disabled DNS Server recursion don't forget to do so according to <a href='https://support.microsoft.com/hr-ba/help/2678371/microsoft-dns-server-vulnerability-to-dns-server-cache-snooping-attack'>'Microsoft DNS Server vulnerability to DNS Server Cache snooping attacks'</a>. Enabling <B>Scavenging</B> is also very important to avoid old records in the DNS. Also verify the <B>forwarders</B> and <B>conditional forwarders</B>.</td></tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR><BR><BR><BR><BR><BR>"



######################################### DCs Health HEADER #############################################

write-host 'Starting DCDiag Reporting..'

add-content $report  "<table width='100%' border='0'>" 
add-content $report  "<tr bgcolor='White'>" 
add-content $report  "<td colspan='7' height='50' align='center'>" 
add-content $report  "<font face='verdana' color='#000000' size='50'>Domain Controller Diagnostic Tool<HR></font>" 
add-content $report  "</td>" 
add-content $report  "</tr>" 
add-content $report  "</table>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>This section will give a detailed view of the Domain Controller's health. With tests and validations based on <B>DCDiag</B> tool and should be enough to give a deep status of Domain Controller’s overall heatlh. </td></tr></TABLE>" 


######################################### DCDiag´s  ###############################################



add-content $report "<BR><BR><BR>"

ForEach ($DC in $DCs)
{

add-content $report  "<table width='50%' border='0'>" 
add-content $report  "<tr bgcolor='White'>" 
add-content $report  "<td colspan='7' height='70' align='left'>" 
add-content $report  "<H2>$DC<HR><H2>" 
add-content $report  "</td>" 
add-content $report  "</tr>" 
add-content $report  "</table>"

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag Reporting of: "+$DC)


$DCD = Import-Clixml -Path ('C:\ADxRay\Hammer\Inv_'+$DC.Name+'.xml')


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

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag initial validation: "+$DC)

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


Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag VerifyReference Test: "+$DC)
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

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag Advertising Test: "+$DC)

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

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag FrsEvent: "+$DC)

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

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag DFSREvent Test: "+$DC)

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

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag SysvolCheck Test: "+$DC)

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

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag KccEvent Test: "+$DC)

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

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag KnowsOfRoleHolders Test: "+$DC)


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

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag MachineAccount Test: "+$DC)



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

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag NCSecDesc Test: "+$DC)

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

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag NetLogons Test: "+$DC)

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

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag ObjectsReplicated: "+$DC)

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

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag Replications: "+$DC)

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

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag RIDManager: "+$DC)

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

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag SystemLog Test: "+$DC)

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

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>This section will give a detailed view of the Domain Controller's Security. This inventory is based on Microsoft´s public best practices and recommendations.</td></tr></TABLE>" 

add-content $report "<BR><BR><BR>"


######################################### DCs Security Log inventory  ###############################################


write-host 'Starting Domain Controller Security Log Reporting..'

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Checking if RSOP Folder already exists.")    

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Begining Domain Controller's Security Log Reporting.")   

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

foreach ($DC in $DCs)
    {
    Try{

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Begining Event Viewer Log Inventory of:"+$DC) 
        
    $DCD = Import-Clixml -Path ('C:\ADxRay\Hammer\Inv_'+$DC+'.xml')

    $SysLogSize = $DCD.DCSysLog
    
    $SecLogSize = $DCD.DCSecLog
    
    $evt = $DCD.CriticalEvts

    $evtclearpw = $DCD.DCCleEvts
    $evtbatch = $DCD.DCBatEvts

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Log sizes adquired:"+$SysLogSize+" , "+$SecLogSize+" and "+$ADLogSize) 

    $Domain = $DC.Domain
    $DCHostName = $DC.name
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
        Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - End of server:"+$DC) 
}
Catch{
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - The following error ocurred during catcher: "+$_.Exception.Message) 
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

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Event log size configuration must be a top priority. Often when those configurations are noticed is already too late. Make sure at least Security and System Events are adjusted to a regular size. This will ensure that vital information is recorded in time of need. Those recommendations were set based on the following pages: <a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd349798(v=ws.10)'>Event Log</a> and <a href='https://docs.microsoft.com/en-us/windows/client-management/mdm/diagnosticlog-csp'>DiagnosticLog CSP</a>. If a SysLog Server is in place in the environment, those numbers may change.</td></tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR><BR><BR><BR><BR><BR>"



######################################### DCs Security HotFix inventory  ###############################################


write-host 'Starting Domain Controllers HotFix Reporting..'

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Begining Domain Controller's Hotfix Reporting.")   

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

foreach ($DC in $DCs)
    {
    Try{

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Begining HotFix Inventory of:"+$DC) 
        
    $DCD = Import-Clixml -Path ('C:\ADxRay\Hammer\Inv_'+$DC+'.xml')

    $Update = $DCD.Hotfix

    $Result = $Update[0] 

    $HFDate = $Result.InstalledOn.ToShortDateString()

    $HFID = $Result.HotFixID

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Latest Hotfix installed on:"+$HFDate)
    
    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Latest Hotfix installed:"+$HFID) 

    $Domain = $DC.Domain
    $DCHostName = $DC.name
    
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
    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - End of Hotfix Inventory for server:"+$DC) 
}
Catch{
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - The following error ocurred during catcher: "+$_.Exception.Message) 
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

write-host 'Starting Domain Controller Security Policies Reporting..'


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


Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Domain Controller Security Policies Reporting") 

Add-Content $report "</tr>" 


foreach ($DC in $DCs)
    {
    try {
    $DCD = Import-Clixml -Path ('C:\ADxRay\Hammer\Inv_'+$DC+'.xml')
    
    $Domain = $DC.Domain
    $DCHostName = $DC.name


    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Reading RSOP result for: " +$DC) 
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
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - The following error ocurred during catcher: "+$_.Exception.Message) 
}

}

Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

if ($SecCount -ge 1 -or $PolCount -ge 1 -or $UsrRCount -ge 1 -or $RegCount -ge 1 -or $FWCount -ge 1)
{

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td bgcolor= 'Red' align=center><font color='#FFFFFF'>Some of Security Policies recommended by Microsoft were not found in those Domain Controllers. Download the latest Security Baseline and apply them in the environment for Workstations, Member Servers and Domain Controllers: <a href='https://www.microsoft.com/en-us/download/details.aspx?id=55319'>Microsoft Security Compliance Toolkit 1.0</a>. Be careful when applying the Microsoft’s Security Baseline in the environment, as some settings may impact the overall experience of end users. Precaution is recommended and testing everything upfront might be a good idea.</font></td></tr></TABLE>" 

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

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Domain Controller User Rights Assignments reporting") 

Add-Content $report "</tr>" 

foreach ($DC in $DCs)
    {
    try {
    $DCD = Import-Clixml -Path ('C:\ADxRay\Hammer\Inv_'+$DC+'.xml')

    $Domain = $DC.Domain
    $DCHostName = $DC.name

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Domain Controller User Rights Assignments on the server: "+$DC) 

    [xml]$XmlDocument = Get-Content -Path ("C:\ADxRay\Hammer\RSOP_"+$DC.Name+".xml")

    $us = $XmlDocument.Rsop.ComputerResults.ExtensionData.Extension.UserRightsAssignment | where {$_.Name -eq 'SeDenyRemoteInteractiveLogonRight' -or $_.Name -eq 'SeDenyBatchLogonRight' -or $_.Name -eq 'SeDenyNetworkLogonRight' -or $_.Name -eq 'SeDenyServiceLogonRight'}

    $dnsvc = ''
    $dnnet = ''
    $dnbat = ''
    $dnrdp = ''

    $dnsvc = $us | where {$_.Name -eq 'SeDenyServiceLogonRight'}
    $dnsvc = $dnsvc.Member.Name.'#text'
    $dnnet = $us | where {$_.Name -eq 'SeDenyNetworkLogonRight'}
    $dnnet = $dnnet.Member.Name.'#text'
    $dnbat = $us | where {$_.Name -eq 'SeDenyBatchLogonRight'}
    $dnbat = $dnbat.Member.Name.'#text'
    $dnrdp = $us | where {$_.Name -eq 'SeDenyRemoteInteractiveLogonRight'}
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


Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Ending Domain Controller User Rights Assignments for: "+$DC)

    Add-Content $report "</tr>" 
}
Catch{
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors found -------------")
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - The following error ocurred during catcher: "+$_.Exception.Message) 
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



######################################### SOFTWARE HEADER #############################################

add-content $report "<div id='Softwares' class='tabcontent'>"

add-content $report  "<table width='100%' border='0'>" 
add-content $report  "<tr bgcolor='White'>" 
add-content $report  "<td colspan='7' height='70' align='center'>" 
add-content $report  "<font face='verdana' color='#000000' size='62'>Installed Softwares<HR></font>" 
add-content $report  "</td>" 
add-content $report  "</tr>" 
add-content $report  "</table>" 

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>This section is intended to give an overall view of the <B>Domain Controller’s Installed Software</B>. The general consensus is that only very essential software should be installed on Domain Controllers. As more applications represent extra attack surfaces. And make sure that if you need to keep that software installed, that you keep them at least updated!</td></tr></TABLE>" 

add-content $report "<BR><BR><BR>"

######################################### SOFTWARE #############################################



######################################### INSTALLED SOFTWARES  ###############################################


write-host 'Starting Domain Controllers Installed Reporting..'

Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Begining Domain Controller's Installed Software Reporting.")   

add-content $report "<CENTER>"
 
add-content $report  "<table width='60%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='5%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Installed Softwares</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Architecture</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Version</B></td>"
Add-Content $report  "<td width='10%' align='center'><B>Publisher</B></td>"

 
Add-Content $report "</tr>" 

foreach ($DC in $DCs) 
    {
    Try{

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Begining Software Reporting of:"+$DC) 
        
    $DCD = Import-Clixml -Path ('C:\ADxRay\Hammer\Inv_'+$DC+'.xml')

    $Software64 = $DCD.InstalledSoftwaresx64   
    $Software86 = $DCD.InstalledSoftwaresx86

    $Domain = $DC.Domain
    $DCHostName = $DC.name

    Foreach ($sw in $Software64)
    {

    if ($sw.DisplayName)
    {

    $SWD = $sw.DisplayName
    $SWDV = $sw.DisplayVersion
    $SWDP = $sw.Publisher

    Add-Content $report "<tr>"

    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DCHostName</td>" 

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Reporting of:"+$SWD)

        if ($SWDP -like '*Microsoft*')
        {

            Add-Content $report "<td bgcolor='White' align=center>$SWD</td>"
            Add-Content $report "<td bgcolor='White' align=center>x64</td>" 
            Add-Content $report "<td bgcolor='White' align=center>$SWDV</td>" 
            Add-Content $report "<td bgcolor='White' align=center>$SWDP</td>" 
        }
    else
        {

           Add-Content $report "<td bgcolor='Red' align=center><font color='#FFFFFF'>$SWD</font></td>" 
           Add-Content $report "<td bgcolor='Red' align=center><font color='#FFFFFF'>x64</font></td>" 
           Add-Content $report "<td bgcolor='Red' align=center><font color='#FFFFFF'>$SWDV</font></td>"  
           Add-Content $report "<td bgcolor='Red' align=center><font color='#FFFFFF'>$SWDP</font></td>"   
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

    Add-Content $report "<tr>"

    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DCHostName</td>" 

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Reporting of:"+$SWD)

        if ($SWDP -like '*Microsoft*')
        {

            Add-Content $report "<td bgcolor='White' align=center>$SWD</td>"
            Add-Content $report "<td bgcolor='White' align=center>x86</td>" 
            Add-Content $report "<td bgcolor='White' align=center>$SWDV</td>" 
            Add-Content $report "<td bgcolor='White' align=center>$SWDP</td>" 
        }
    else
        {

           Add-Content $report "<td bgcolor='Red' align=center><font color='#FFFFFF'>$SWD</font></td>" 
           Add-Content $report "<td bgcolor='Red' align=center><font color='#FFFFFF'>x86</font></td>" 
           Add-Content $report "<td bgcolor='Red' align=center><font color='#FFFFFF'>$SWDV</font></td>"  
           Add-Content $report "<td bgcolor='Red' align=center><font color='#FFFFFF'>$SWDP</font></td>"   
        }
   
    Add-Content $report "</tr>" 
    }
    }

    Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - End of Software Reporting for server:"+$DC) 
}
Catch{
Add-Content $ADxRayLog ((get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - The following error ocurred during Reporting: "+$_.Exception.Message) 
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

write-host 'Starting ADxRay Version Validation..'

$VerValid = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Merola132/ADxRay/master/Docs/VersionControl" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -TimeoutSec 5
if ($VerValid.StatusCode -eq 200) 
    {
        if (($VerValid.Content[0]+$VerValid.Content[1]+$VerValid.Content[2]) -eq $Ver) 
            {
                Write-Host ('Version: '+$Ver+' - This Version is up to date.') -ForegroundColor Green
            }
        else 
            {
                Write-Host ('Version: '+$Ver+' - This version of ADxRay is outdated. Please access https://github.com/Merola132/ADxRay for the lastest version and corrections.') -ForegroundColor Red
            }
    }
elseif ($VerValid -eq $null ) 
    {
        Write-Host ('Version: '+$Ver+' - ADxRay version validation was not possible. Please access https://github.com/Merola132/ADxRay for the lastest version and corrections.') -ForegroundColor Red
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


Hammer
sleep 10
Report






######################################### ADDING TIME MEASURE #############################################

}
$Measure = $Runtime.Totalminutes.ToString('#######.##')

#$report = ("C:\ADxRay\ADxRay_Report_"+(get-date -Format 'yyyy-MM-dd')+".htm") 

$index = Get-Content $report

$Index[44] = "<TABLE BORDER=0 WIDTH=20% align='right'><tr><td align='right'><font face='verdana' color='#000000' size='4'> Execution: $Measure Minutes<HR></font></td></tr></TABLE>"

$index | out-file $report

sleep 5

Invoke-Item $report















