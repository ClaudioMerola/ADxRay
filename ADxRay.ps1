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

# Version
$Ver = '1.3'

write-host 'Starting ADxRay Script'

$Runtime = Measure-Command -Expression {
if ((Test-Path -Path C:\ADxRay -PathType Container) -eq $false) {New-Item -Type Directory -Force -Path C:\ADxRay}

$report = ("C:\ADxRay\ADxRay_Report_"+(get-date -Format 'yyyy-MM-dd')+".htm") 
if ((test-path $report) -eq $false) {new-item $report -Type file -Force}
Clear-Content $report 

$ADxRayLog = "C:\ADxRay\ADxRay.log"
if ((test-path $ADxRayLog) -eq $false) {new-item $ADxRayLog -Type file -Force}
Clear-Content $ADxRayLog 

$Forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()

$ErrorActionPreference = "silentlycontinue"

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
add-content $report  "-->" 
add-content $report  "</style>" 
Add-Content $report "</head>" 
Add-Content $report "<body LINK='Black' VLINK='Black'>" 

######################################### HEADER #############################################

add-content $report "<BR>"
add-content $report  "<table width='100%'>" 
add-content $report  "<tr>" 
add-content $report  "<td colspan='7' height='130' align='center' bgcolor='Black'>" 
add-content $report  "<font face='tahoma' color='#0000FF' size='75'><strong><a href='https://github.com/Merola132/ADxRay'>Active Directory xRay Report</a></strong></font>" 
add-content $report  "</td>"  
add-content $report  "</tr>"
Add-Content $report "<tr><td><font face='tahoma' color='#000000' size='2'><strong>Version: $Ver</font></td></tr>"  
add-content $report  "</table>"
add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td><font face='verdana' size='1'>This Report is intended to help network administrators and contractors to get a better understanding and overview of the actual status and health of their Active Directory Forest, Domains, Domain Controllers, DNS Servers and Active Directory objects such as User Accounts, Computer Accounts, Groups and Group Policies. This report has been tested in several Active Directory topologies and environments without further problems or impacts in the server or environment´s performance. If you however experience some sort of problem while running this script/report. Feel free to send that feedback and we will help to investigate as soon as possible (feedback information’s are presented at the end of this report). Thanks for using.</font></td></tr></TABLE>"
add-content $report "<BR><BR>"



######################################### FOREST HEADER #############################################


add-content $report  "<table width='100%' border='0'>" 
add-content $report  "<tr bgcolor='White'>" 
add-content $report  "<td colspan='7' height='70' align='center'>" 
add-content $report  "<font face='verdana' color='#000000' size='62'>Active Directory Forest<HR></font>" 
add-content $report  "</td>" 
add-content $report  "</tr>" 
add-content $report  "</table>" 

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>This section is intended to give an overall view of the <B>Active Directory Forest</B>, as so as the <B>Active Directory Domains</B> and <B>Domain Controllers</B> and configured <B>Trusts</B> between Active Directory Domains and others Active Directory Forests.</td></tr></TABLE>" 

add-content $report "<BR><BR><BR>"

##################################### SCORE COUNTERS ###########################################


$ScoreCount = 0
$ScoreLimit = 0


######################################### FOREST #############################################

Add-Content $ADxRayLog ("ForestLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Forest data catcher")
Add-Content $ADxRayLog ("ForestLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Forest: "+$Forest)

write-host 'Starting Forest Analysis..'

try{
add-content $report "<div id='ForestOverview'></div>"

add-content $report  "<CENTER>"
add-content $report  "<h3>Active Directory Forest View ($Forest)</h3>" 
add-content $report  "</CENTER>"
add-content $report "<BR>"

add-content $report  "<table width='40%' align='center' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
 
Add-Content $report "</tr>" 

$ForeName = $Forest.Name
$Dom = $Forest.Domains
$RecycleBin = if ((Get-ADOptionalFeature -Filter * | Where {$_.Name -eq 'Recycle Bin Feature' -and $_.EnabledScopes -ne '' })) {'Enabled'}else{'Not Enabled'}
$ForeMode = $Forest.ForestMode
$ForeGC = $Forest.GlobalCatalogs
$ForeSites = $Forest.Sites

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
$ScoreLimit ++
    if ($ForeMode -like '*NT*' -or $ForeMode -like '*2000*' -or $ForeMode -like '*2003*')
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$ForeMode</font></td>" 
        }
    elseif ($ForeMode -like '*2008*' -and $ForeMode -notlike '*2008R2*') 
        {
            Add-Content $report "<td bgcolor= 'Yellow' align=center>$ForeMode</td>" 
        }
    elseif ($ForeMode -like '*2012*' -or $ForeMode -like '*2016*') 
        {
            $ScoreCount ++        
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
$ScoreLimit ++
    if ($RecycleBin -ne 'Enabled')
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$RecycleBin</font></td>" 
        }
    else
        {
            $ScoreCount ++
            Add-Content $report "<td bgcolor= 'Lime' align=center>$RecycleBin</td>" 
        }
Add-Content $report "</tr>" 
Add-Content $report "<tr>" 
Add-Content $report  "<th bgcolor='WhiteSmoke' font='tahoma'><B>Sites</B></th>" 
Add-Content $report "<td bgcolor='White' align=center>$ForeSites</td>" 

Add-Content $report "</tr>" 
Add-Content $ADxRayLog ("ForestLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - RecycleBin status: "+$RecycleBin)

Add-Content $ADxRayLog ("ForestLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - End of Forest inventory phase.")


}
Catch { 
Add-Content $ADxRayLog ("ForestLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors found -------------")
Add-Content $ADxRayLog ("ForestLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - The following error ocurred during catcher: "+$_.Exception.Message)
}
Add-Content $ADxRayLog ("ForestLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - End of log file")

Add-content $report  "</table>"

add-content $report "<BR><BR><BR><BR>"



######################################### TRUST #############################################

write-host 'Starting Trust Analysis..'

Add-Content $ADxRayLog ("TrustLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Trust data catcher")
Add-Content $ADxRayLog ("TrustLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Forest: "+$Forest)

try{

add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>Active Directory Trusts View ($Forest)</h3>" 
add-content $report  "</CENTER>"
add-content $report "<BR>"
 

$Trust1 = Get-ADtrust -Filter * -Server $Forest.SchemaRoleOwner -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

add-content $report  "<table width='80%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='10%' align='center'><B>Source</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Trusted Domain</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>Type</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>ForestTransitive</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>IntraForest</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>SID Filtering</B></td>"

 
Add-Content $report "</tr>" 

Foreach ($T2 in $Trust1)
    {
        Add-Content $report "<tr>" 
        $T3Source = $T2.Source
        $T3Target = $T2.Target
        $T3Dir = $T2.Direction
        $T3Trans = $T2.ForestTransitive
        $T3Intra = $T2.IntraForest
        $T3SIDFil = $T2.SIDFilteringForestAware

        Add-Content $ADxRayLog ("TrustLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Trust Found for: "+$T3Source+ " To "+$T3Target)
    
        Add-Content $report "<td bgcolor='White' align=center>$T3Source</td>" 
        Add-Content $report "<td bgcolor='White' align=center>$T3Target</td>" 
        Add-Content $report "<td bgcolor='White' align=center>$T3Dir</td>" 
        Add-Content $report "<td bgcolor='White' align=center>$T3Trans</B></td>" 
        Add-Content $report "<td bgcolor='White' align=center>$T3Intra</td>" 
        Add-Content $report "<td bgcolor='White' align=center>$T3SIDFil</td>" 

        Add-Content $report "</tr>" 
    }

Add-Content $ADxRayLog ("TrustLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - End of Trust inventory phase.")

}
Catch { 
Add-Content $ADxRayLog ("TrustLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors found -------------")
Add-Content $ADxRayLog ("TrustLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - The following error ocurred during catcher: "+$_.Exception.Message)
}
Add-Content $ADxRayLog ("TrustLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - End of TRUST capture phase.")

Add-content $report  "</table>"

add-content $report "</CENTER>"

add-content $report "<BR><BR><BR><BR>"


######################################### DOMAIN #############################################

write-host 'Starting Domains Analysis..'

Add-Content $ADxRayLog ("DomainLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Domains data catcher")
Add-Content $ADxRayLog ("DomainLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Forest: "+$Forest)


add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>Active Directory Domains View ($Forest)</h3>" 
add-content $report  "</CENTER>"
add-content $report "<BR>"
 
add-content $report  "<table width='80%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='5%' align='center'><B>Topology</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>Forest Name</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>Domain Name</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Parent Domain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>ChildDomain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain Functional Level</B></td>"
Add-Content $report  "<td width='10%' align='center'><B>Default Computer Container</B></td>"
Add-Content $report  "<td width='10%' align='center'><B>Default User Container</B></td>" 

Try{

Add-Content $report "</tr>" 

Foreach ($Domain0 in $Forest.Domains.Name)
    {
    $Domain1 = Get-ADDomain -Identity $Domain0 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

    Add-Content $report "<tr>" 
    
    $D2Name = $Domain1.DNSRoot
    $D2Parent = $Domain0.ParentDomain
    $D2Child = $Domain1.ChildDomains
    $D2Mode = $Domain1.DomainMode
    $D2CompCont = $Domain1.ComputersContainer
    $D2UserCont = $Domain1.UsersContainer
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


    Add-Content $ADxRayLog ("DomainLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Inventoring the following domain: "+$D2Name)

    Add-Content $report "<td bgcolor='White' align=center>$ForeName</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$D2Name</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$D2Parent</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$D2Child</B></td>" 
    $ScoreLimit ++
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
            $ScoreCount ++
            Add-Content $report "<td bgcolor= 'Lime' align=center>$D2Mode</td>" 
        }
    else
        {
            Add-Content $report "<td bgcolor='White' align=center>$D2Mode</td>" 
        }
    Add-Content $report "<td bgcolor='White' align=center>$D2CompCont</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$D2UserCont</td>" 

    Add-Content $report "</tr>" 

    }

Add-Content $ADxRayLog ("DomainLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Domain inventory finished")


}
Catch { 
Add-Content $ADxRayLog ("DomainLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors found -------------")
Add-Content $ADxRayLog ("DomainLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - The following error ocurred during catcher: "+$_.Exception.Message)
}
Add-Content $ADxRayLog ("DomainLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - End of Domain phase.")

Add-content $report  "</table>"

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Domain's design must be as clear as possible and always based on best practices. Remember to consult <a href='https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/creating-a-site-design'>Creating a Site Design</a> and <a href='https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/determining-the-number-of-domains-required'>Determining the Number of Domains Required</a> before adding any new Domains in the topology.</td></tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR><BR><BR><BR>"


######################################### DC #############################################

write-host 'Starting Domain Controller Analysis..'

Add-Content $ADxRayLog ("DomainControllersLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Domain Controllers data catcher")
Add-Content $ADxRayLog ("DomainControllersLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Forest: "+$Forest)

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
Add-Content $report  "<td width='5%' align='center'><B>Global Catalog</B></td>" 
Add-Content $report  "<td width='15%' align='center'><B>Operating System</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>Build</B></td>"
Add-Content $report  "<td width='10%' align='center'><B>FSMO</B></td>"
Add-Content $report  "<td width='10%' align='center'><B>Site</B></td>"
 
Add-Content $report "</tr>" 

$DCs = $Forest.domains | ForEach-Object {$_.DomainControllers} | ForEach-Object {$_.Name} 

foreach ($DC in $DCs)
    {
    Try{
    Add-Content $ADxRayLog ("DomainControllersLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Inventory of: "+$DC)

    $DCD = Get-ADDomainController -Server $DC -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    $DCD = $DCD | Sort-Object

    $Domain = $DCD.Domain
    $DCHostName = $DCD.Hostname
    $DCEnabled = $DCD.IsReadOnly
    $DCIP = $DCD.IPv4Address
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

    Add-Content $ADxRayLog ("DomainControllersLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Reporting IP of: "+$DCHostName)

    Add-Content $report "<td bgcolor='White' align=center>$DCIP</td>" 

    Add-Content $ADxRayLog ("DomainControllersLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Reporting Global Catalog of: "+$DCHostName)

    Add-Content $report "<td bgcolor='White' align=center>$DCGC</td>" 

    Add-Content $ADxRayLog ("DomainControllersLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Reporting Operating System Version of: "+$DCHostName)
    $ScoreLimit ++
        if ($DCOS -like '* NT*' -or $DCOS -like '* 2000*' -or $DCOS -like '* 2003*')
        {
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$DCOS</font></td>" 
        }
    elseif ($DCOS -like '* 2008*' -or $DCOS -like '* 2008 R2*') 
        {
            Add-Content $report "<td bgcolor= 'Yellow' align=center>$DCOS</td>" 
        }
    elseif ($DCOS -like '* 2012*' -or $DCOS -like '* 2016*') 
        {
            $ScoreCount ++
            Add-Content $report "<td bgcolor= 'Lime' align=center>$DCOS</td>" 
        }
    else
        {
            Add-Content $report "<td bgcolor='White' align=center>$DCOS</td>" 
        }
     
    Add-Content $report "<td bgcolor='White' align=center>$DCOSD</td>" 

    Add-Content $ADxRayLog ("DomainControllersLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Reporting FSMO of: "+$DCHostName)

    Add-Content $report "<td bgcolor='White' align=center>$FSMO</td>" 

    Add-Content $ADxRayLog ("DomainControllersLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Reporting Site of: "+$DCHostName)

    Add-Content $report "<td bgcolor='White' align=center>$Site</td>" 
    
    Add-Content $report "</tr>" 

    }
    Catch 
            { 
    Add-Content $ADxRayLog ("DomainControllersLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors found -------------")
    Add-Content $ADxRayLog ("DomainControllersLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - The following error ocurred during catcher: "+$_.Exception.Message)    
            }
    }


Add-Content $ADxRayLog ("DomainControllersLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Domain Controllers inventoring finished")

Add-Content $ADxRayLog ("DomainControllersLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - End of general Domain Controller´s phase")

Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Many Domain Controllers does not represent a problem. But using an oversized topology might increase the administrative effort and decrease the security of the environment as every writable Domain Controller have a full copy of every user account along with their password. Make sure to keep a reasonable number of Domain Controllers and keep they secured as possible.</td></tr></TABLE>" 

add-content $report  "</CENTER>"

write-host 'Domain Controller Initial Inventory Done.'

add-content $report "<BR><BR><BR><BR><BR><BR>"




######################################### DCs HEADER #############################################

write-host 'Starting DCDiag..'

add-content $report  "<table width='100%' border='0'>" 
add-content $report  "<tr bgcolor='White'>" 
add-content $report  "<td colspan='7' height='70' align='center'>" 
add-content $report  "<font face='verdana' color='#000000' size='62'>Domain Controller´s Health<HR></font>" 
add-content $report  "</td>" 
add-content $report  "</tr>" 
add-content $report  "</table>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>This section will give a detailed view of the Domain Controller's health. With tests and validations based on <B>DCDiag</B> tool and should be enough to give a deep status of Domain Controllers.</td></tr></TABLE>" 


######################################### DCDiag´s  ###############################################



add-content $report "<BR><BR><BR>"

Get-Job | Remove-Job

start-job -scriptblock {dcdiag /e /s:$args} -ArgumentList ($Forest.SchemaRoleOwner.Name)
Get-Job | Wait-Job
$Job = Get-Job

$DCDiag = Receive-Job -Job $job

Write-Host ('DCDiag Done. Starting Analysis of: ') -NoNewline
write-host $DCs.Count -NoNewline -ForegroundColor Magenta
Write-Host ' DCs'

ForEach ($DC in $DCs)
{

add-content $report  "<table width='50%' border='0'>" 
add-content $report  "<tr bgcolor='White'>" 
add-content $report  "<td colspan='7' height='70' align='left'>" 
add-content $report  "<H2>$DC<HR><H2>" 
add-content $report  "</td>" 
add-content $report  "</tr>" 
add-content $report  "</table>"

Add-Content $ADxRayLog ("DomainControllersLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag Inventory of: "+$DC)

$DC = $DC.ToString()
$DC2 = $DC.split(' ')
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

Add-Content $ADxRayLog ("DomainControllersLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag initial validation: "+$DC)

if(($DCDiag | Select-String -Pattern ($DC +' passed test Connectivity')).Count -eq $true) 
    {
            $Status = $DCDiag | Select-String -Pattern ($DC +' passed test Connectivity')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCDiag | Select-String -Pattern ($DC +' failed test Connectivity')).Count -eq $true) 
                {
                    $Status = $DCDiag | Select-String -Pattern ($DC +' failed test Connectivity')
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

Add-Content $ADxRayLog ("DomainControllersLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag VerifyReference Test: "+$DC)
$ScoreLimit ++
if(($DCDiag | Select-String -Pattern ($DC +' passed test VerifyReferences')).Count -eq $true) 
    {
            $ScoreCount ++
            $Status = $DCDiag | Select-String -Pattern ($DC +' passed test VerifyReferences')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCDiag | Select-String -Pattern ($DC +' failed test VerifyReferences')).Count -eq $true) 
                {
                    $Status = $DCDiag | Select-String -Pattern ($DC +' failed test VerifyReferences')
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

Add-Content $ADxRayLog ("DomainControllersLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag Advertising Test: "+$DC)

if(($DCDiag | Select-String -Pattern ($DC +' passed test Advertising')).Count -eq $true) 
    {
            $Status = $DCDiag | Select-String -Pattern ($DC +' passed test Advertising')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCDiag | Select-String -Pattern ($DC +' failed test Advertising')).Count -eq $true) 
                {
                    $Status = $DCDiag | Select-String -Pattern ($DC +' failed test Advertising')
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

Add-Content $ADxRayLog ("DomainControllersLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag FrsEvent: "+$DC)

if(($DCDiag | Select-String -Pattern ($DC +' passed test FrsEvent')).Count -eq $true) 
    {
            $Status = $DCDiag | Select-String -Pattern ($DC +' passed test FrsEvent')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCDiag | Select-String -Pattern ($DC +' failed test FrsEvent')).Count -eq $true) 
                {
                    $Status = $DCDiag | Select-String -Pattern ($DC +' failed test FrsEvent')
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

Add-Content $ADxRayLog ("DomainControllersLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag DFSREvent Test: "+$DC)

if(($DCDiag | Select-String -Pattern ($DC +' passed test DFSREvent')).Count -eq $true) 
    {
            $Status = $DCDiag | Select-String -Pattern ($DC +' passed test DFSREvent')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCDiag | Select-String -Pattern ($DC +' failed test DFSREvent')).Count -eq $true) 
                {
                    $Status = $DCDiag | Select-String -Pattern ($DC +' failed test DFSREvent')
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

Add-Content $ADxRayLog ("DomainControllersLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag SysvolCheck Test: "+$DC)

if(($DCDiag | Select-String -Pattern ($DC +' passed test SysVolCheck')).Count -eq $true) 
    {
            $Status = $DCDiag | Select-String -Pattern ($DC +' passed test SysVolCheck')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCDiag | Select-String -Pattern ($DC +' failed test SysVolCheck')).Count -eq $true) 
                {
                    $Status = $DCDiag | Select-String -Pattern ($DC +' failed test SysVolCheck')
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

Add-Content $ADxRayLog ("DomainControllersLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag KccEvent Test: "+$DC)

if(($DCDiag | Select-String -Pattern ($DC +' passed test KccEvent')).Count -eq $true) 
    {
            $Status = $DCDiag | Select-String -Pattern ($DC +' passed test KccEvent')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCDiag | Select-String -Pattern ($DC +' failed test KccEvent')).Count -eq $true) 
                {
                    $Status = $DCDiag | Select-String -Pattern ($DC +' failed test KccEvent')
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

Add-Content $ADxRayLog ("DomainControllersLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag KnowsOfRoleHolders Test: "+$DC)


if(($DCDiag | Select-String -Pattern ($DC +' passed test KnowsOfRoleHolders')).Count -eq $true) 
    {
            $Status = $DCDiag | Select-String -Pattern ($DC +' passed test KnowsOfRoleHolders')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCDiag | Select-String -Pattern ($DC +' failed test KnowsOfRoleHolders')).Count -eq $true) 
                {
                    $Status = $DCDiag | Select-String -Pattern ($DC +' failed test KnowsOfRoleHolders')
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

Add-Content $ADxRayLog ("DomainControllersLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag MachineAccount Test: "+$DC)



if(($DCDiag | Select-String -Pattern ($DC +' passed test MachineAccount')).Count -eq $true) 
    {
            $Status = $DCDiag | Select-String -Pattern ($DC +' passed test MachineAccount')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCDiag | Select-String -Pattern ($DC +' failed test MachineAccount')).Count -eq $true) 
                {
                    $Status = $DCDiag | Select-String -Pattern ($DC +' failed test MachineAccount')
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

Add-Content $ADxRayLog ("DomainControllersLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag NCSecDesc Test: "+$DC)

if(($DCDiag | Select-String -Pattern ($DC +' passed test NCSecDesc')).Count -eq $true) 
    {
            $Status = $DCDiag | Select-String -Pattern ($DC +' passed test NCSecDesc')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCDiag | Select-String -Pattern ($DC +' failed test NCSecDesc')).Count -eq $true) 
                {
                    $Status = $DCDiag | Select-String -Pattern ($DC +' failed test NCSecDesc')
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

Add-Content $ADxRayLog ("DomainControllersLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag NetLogons Test: "+$DC)

if(($DCDiag | Select-String -Pattern ($DC +' passed test NetLogons')).Count -eq $true) 
    {
            $Status = $DCDiag | Select-String -Pattern ($DC +' passed test NetLogons')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCDiag | Select-String -Pattern ($DC +' failed test NetLogons')).Count -eq $true) 
                {
                    $Status = $DCDiag | Select-String -Pattern ($DC +' failed test NetLogons')
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

Add-Content $ADxRayLog ("DomainControllersLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag ObjectsReplicated: "+$DC)

if(($DCDiag | Select-String -Pattern ($DC +' passed test ObjectsReplicated')).Count -eq $true) 
    {
            $Status = $DCDiag | Select-String -Pattern ($DC +' passed test ObjectsReplicated')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCDiag | Select-String -Pattern ($DC +' failed test ObjectsReplicated')).Count -eq $true) 
                {
                    $Status = $DCDiag | Select-String -Pattern ($DC +' failed test ObjectsReplicated')
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

Add-Content $ADxRayLog ("DomainControllersLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag Replications: "+$DC)

if(($DCDiag | Select-String -Pattern ($DC +' passed test Replications')).Count -eq $true) 
    {
            $Status = $DCDiag | Select-String -Pattern ($DC +' passed test Replications')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCDiag | Select-String -Pattern ($DC +' failed test Replications')).Count -eq $true) 
                {
                    $Status = $DCDiag | Select-String -Pattern ($DC +' failed test Replications')
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

Add-Content $ADxRayLog ("DomainControllersLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag RIDManager: "+$DC)

if(($DCDiag | Select-String -Pattern ($DC +' passed test RidManager')).Count -eq $true) 
    {
            $Status = $DCDiag | Select-String -Pattern ($DC +' passed test RidManager')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCDiag | Select-String -Pattern ($DC +' failed test RidManager')).Count -eq $true) 
                {
                    $Status = $DCDiag | Select-String -Pattern ($DC +' failed test RidManager')
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

if(($DCDiag | Select-String -Pattern ($DC +' passed test Services')).Count -eq $true) 
    {
            $Status = $DCDiag | Select-String -Pattern ($DC +' passed test Services')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCDiag | Select-String -Pattern ($DC +' failed test Services')).Count -eq $true) 
                {
                    $Status = $DCDiag | Select-String -Pattern ($DC +' failed test Services')
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

Add-Content $ADxRayLog ("DomainControllersLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DCDiag SystemLog Test: "+$DC)

if(($DCDiag | Select-String -Pattern ($DC +' passed test SystemLog')).Count -eq $true) 
    {
            $Status = $DCDiag | Select-String -Pattern ($DC +' passed test SystemLog')
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Status</td>"
    }
    else {
            if(($DCDiag | Select-String -Pattern ($DC +' failed test SystemLog')).Count -eq $true) 
                {
                    $Status = $DCDiag | Select-String -Pattern ($DC +' failed test SystemLog')
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

add-content $report "<BR><BR>"

}


add-content $report "<BR><BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Checks that all application directory partitions have appropriate security descriptor reference domains. For more details regarding the tool, check '<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731968(v%3Dws.11)'>DCDiag</a>'.Also, verify '<a href='https://blogs.technet.microsoft.com/askds/2011/03/22/what-does-dcdiag-actually-do/'>What does DCDiag actually do</a>' for further understanding.</td></tr></TABLE>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Obs. Before the main test is made, the basic connectivity with the DC (DNS check, ICMP and RPC) is validated. This validation also includes LDAP binding (<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755809(v=ws.10)'>How Active Directory Searches Work</a>).</td></tr></TABLE><BR>" 

add-content $report  "</CENTER>"

add-content $report "<BR><BR><BR><BR><BR><BR>"


######################################### SYSVOL FOLDER HEADER #############################################


write-host 'Starting Sysvol Analysis..'

add-content $report  "<table width='100%' border='0'>" 
add-content $report  "<tr bgcolor='White'>" 
add-content $report  "<td colspan='7' height='70' align='center'>" 
add-content $report  "<font face='verdana' color='#000000' size='62'>SYSVOL Folder Status<HR></font>" 
add-content $report  "</td>" 
add-content $report  "</tr>" 
add-content $report  "</table>" 

add-content $report "<BR><BR><BR><BR><BR><BR>"


######################################### SYSVOL #############################################

Add-Content $ADxRayLog ("SYSVolLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting SysVol Inventory")

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

Foreach ($dom in $Forest.Domains.name){

$SYSVOLFOLDER = ('\\'+$dom+'\SYSVOL\'+$dom)

      $SYSVOL = Get-ChildItem  -path $SYSVOLFOLDER -Recurse | Where-Object -FilterScript {$_.PSIsContainer -eq $false} | Group-Object -Property Extension | ForEach-Object -Process {
New-Object -TypeName PSObject -Property @{
        'Extension'= $_.name
        'Count' = $_.count
        'TotalSize (MB)'= '{0:N2}' -f ((($_.group | Measure-Object length -Sum).Sum) /1MB)
        'TotalSize'    = (($_.group | Measure-Object length -Sum).Sum)
    } 
} | Sort-Object -Descending -Property 'Totalsize'


Foreach ($Sys in $SYSVOL)
{
$EXTDOM = $dom
$SYSEXT = $sys.Extension
$SYSCOUNT = $sys.Count
$SYSSIZE = $sys.'TotalSize (MB)'

                if ($SYSSIZE -ge 0.01)
                {

                Add-Content $report "<tr>"

                Add-Content $report "<td bgcolor= 'White' align=center>$EXTDOM</td>"

                if ($SYSEXT -notin ('.bat','.exe','.nix','.vbs','.pol','.reg','.xml','.admx','.adml','.inf','.ini','.adm','.kix','.msi','.ps1','.cmd','.ico'))
                    {
                        $ScoreLimit ++
                        Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$SYSEXT</font></td>" 
                    }
                else  
                    {
                        Add-Content $report "<td bgcolor= 'White' align=center>$SYSEXT</td>"
                    }
                Add-Content $ADxRayLog ("SYSVolLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - "+$SYSEXT+" extension found, total of: "+$SYSCOUNT+" files ("+$SYSSIZE+")")
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

Add-Content $ADxRayLog ("SYSVolLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - End of SYSVol Inventory")

Add-content $report  "</table>"

add-content $report "</CENTER>"

add-content $report "<BR><BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Sysvol folder contain the Group Policies physical files and scripts used in GPOs, those folders are replicated between Domain Controllers from time to time, is very important to only keep essential files in Sysvol as so as keep the folder's size at the very minimum.</td></tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR><BR><BR><BR><BR><BR>"



######################################### DNS HEADER #############################################

write-host 'Starting DNS Analysis..'

add-content $report  "<table width='100%' border='0'>" 
add-content $report  "<tr bgcolor='White'>" 
add-content $report  "<td colspan='7' height='70' align='center'>" 
add-content $report  "<font face='verdana' color='#000000' size='62'>DNS Servers<HR></font>" 
add-content $report  "</td>" 
add-content $report  "</tr>" 
add-content $report  "</table>" 

add-content $report "<BR><BR><BR><BR><BR><BR>"


######################################### DNS Server #############################################

Add-Content $ADxRayLog ("DNSServerLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting DNS Server data catcher")
Add-Content $ADxRayLog ("DNSServerLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Forest: "+$Forest)

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

foreach ($DNSdomain in $Forest.domains)
    {
        $DCs = $DNSDomain.DomainControllers.name

        foreach ($DC in $DNSDomain.DomainControllers.Name)
            {
                Try{
                remove-variable ldapRR
                Add-Content $ADxRayLog ("DNSServerLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Inventoring DNS Server: "+$DC)
                $DNS = Get-DnsServer -ComputerName $DC -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                try{$ldapRR = Get-DnsServerResourceRecord -ZoneName ('_msdcs.'+$DNSdomain) -Name '_ldap._tcp.dc' -ComputerName $DC}
                catch {$ldapRR = Get-DnsServerResourceRecord -ZoneName $DNSdomain -Name '_ldap._tcp.dc._msdcs' -ComputerName $DC}
                    

                $DNSSRVRR = 'Ok'
                Foreach ($DCOne in $DCs)
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

                Add-Content $ADxRayLog ("DNSServerLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Validating DNS Server: "+$DNSName)

                Add-Content $report "<tr>"
                $ScoreLimit ++
                Add-Content $report "<td bgcolor='White' align=center>$DNSName</td>" 
                if ($DNSSca -eq $true)
                    {
                        $ScoreCount ++
                        Add-Content $report "<td bgcolor= 'Lime' align=center>$DNSSca</td>"
                    }
                else  
                    { 
                        Add-Content $report "<td bgcolor= 'Yellow' align=center>$DNSSca</td>" 
                    }
                Add-Content $report "<td bgcolor='White' align=center>$DNSZoneCount</td>" 

                Add-Content $report "<td bgcolor='White' align=center>$DNSZoneScavenge</td>" 
                $ScoreLimit ++
                if ($DNSRootC -eq '' -or $DNSRootC -eq 0)
                    {
                        $ScoreCount ++
                        Add-Content $report "<td bgcolor= 'Lime' align=center>0</td>"
                    }
                else  
                    { 
                        Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$DNSRootC</font></td>" 
                    }

                $ScoreLimit ++
                if ($DNSSRVRR -eq 'Missing')
                    {
                        Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$DNSSRVRR</font></td>" 
                    }
                else  
                    {
                        $ScoreCount ++ 
                        Add-Content $report "<td bgcolor= 'Lime' align=center>$DNSSRVRR</td>"
                    }

                $ScoreLimit ++
                if ($DNSRecur -eq $false)
                    {
                        $ScoreCount ++
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
Add-Content $ADxRayLog ("DNSServerLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors were found during the DNS Server Inventoring -------------")
Add-Content $ADxRayLog ("DNSServerLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - The following error ocurred during catcher: "+$_.Exception.Message)
}

}
}


Add-Content $ADxRayLog ("DNSServerLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - DNS Servers Inventory finished")

Add-content $report  "</table>"

add-content $report "</CENTER>"

add-content $report "<BR><BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td> DNS Server is an important part of Active Directory so it's maintenance is very critical for the safety and funtionality of the environment, if you did not disabled recursion don't forget to do so according to <a href='https://support.microsoft.com/hr-ba/help/2678371/microsoft-dns-server-vulnerability-to-dns-server-cache-snooping-attack'>'Microsoft DNS Server vulnerability to DNS Server Cache snooping attacks'</a>. Enabling <B>Scavaging</B> is also very important to avoid old records in the DNS. Also verify the <B>forwarders</B> and <B>conditional forwarders</B>.</td></tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR><BR><BR><BR><BR><BR>"


######################################### AD OBJECTS HEADER #############################################

write-host 'Starting AD Object Analysis..'

add-content $report  "<table width='100%' border='0'>" 
add-content $report  "<tr bgcolor='White'>" 
add-content $report  "<td colspan='7' height='70' align='center'>" 
add-content $report  "<font face='tahoma' color='#000000' size='62'>Users and Computers<HR></font>" 
add-content $report  "</td>" 
add-content $report  "</tr>" 
add-content $report  "</table>" 

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>This section should give a overall perspective of the user accounts in the environment. As so as the overall maintenance and health of the user accounts in the environment. Verify the informations reported from time to time to keep your environment healthy and to prevent futher problems and security risks regarding user accounts.</td></tr></TABLE>" 


add-content $report "<BR><BR><BR><BR><BR><BR>"

######################################### USERS #############################################

Add-Content $ADxRayLog ("UserDetailsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting User Accounts data catcher")
Add-Content $ADxRayLog ("UserDetailsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Forest: "+$Forest)


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

Foreach ($Contr in $Forest.domains.PdcRoleOwner) 
    {
        Try{
        $UsDomain = $Contr.Domain
        $AllUsers = (dsquery * -filter sAMAccountType=805306368 -s $Contr -attr samAccountName -attrsonly -limit 0).Count

        $UsersDisabled = (dsquery user -disabled -s $Contr -limit 0).Count
        $UsersEnabled = ($AllUsers - $UsersDisabled)
        $UsersInactive = (dsquery user -inactive 12 -s $Contr -limit 0).Count
        $UsersPWDNeverExpire = (dsquery user -stalepwd 0 -s $Contr -limit 0).Count

        Add-Content $ADxRayLog ("UserDetailsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Inventoring User Accounts in the Domain: "+$UsDomain)
        Add-Content $ADxRayLog ("UserDetailsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Total users found: "+$AllUsers)

        Add-Content $report "<tr>" 

        Add-Content $report "<td bgcolor='White' align=center>$UsDomain</td>" 
        Add-Content $report "<td bgcolor='White' align=center>$AllUsers</td>"         
        Add-Content $report "<td bgcolor='White' align=center>$UsersEnabled</td>"               
        Add-Content $report "<td bgcolor='White' align=center>$UsersDisabled</td>"    
        $ScoreLimit ++
        if ($UsersInactive -eq '' -or $UsersInactive -eq 0) 
            {
                $ScoreCount ++
                Add-Content $report "<td bgcolor= 'Lime' align=center>0</td>"
            }
        else 
            { 
                Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$UsersInactive</font></td>" 
            }
        $ScoreLimit ++
        if ($UsersPWDNeverExpire -eq '' -or $UsersPWDNeverExpire -eq 0) 
            {
                $ScoreCount ++
                Add-Content $report "<td bgcolor= 'Lime' align=center>0</td>"
            }
        else 
            { 
                Add-Content $report "<td bgcolor= 'Yellow' align=center>$UsersPWDNeverExpire</td>" 
            }



    Add-Content $report "</tr>"
    }
Catch { 
Add-Content $ADxRayLog ("UserDetailsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors were found during the User Accounts Inventoring -------------")
Add-Content $ADxRayLog ("UserDetailsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - The following error ocurred during catcher: "+$_.Exception.Message)
}
    }


Add-Content $ADxRayLog ("UserDetailsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - User Accounts Inventory finished")

Add-Content $ADxRayLog ("UserDetailsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - End of User Account phase.")
 
Add-content $report  "</table>" 

add-content $report "<BR><BR>"

add-content $report "<TABLE BORDER=0 WIDTH=95%><tr><td>This overview state of user accounts will present the <B>Total number of users</b>, the <B>Disabled User Accounts</B>, <B>Inactive Users </B> and User Accounts that never changed they passwords (that are probabily <B>'Password Never Expires'</B> accounts). Most of those counters should be <B>0</B> or the smallest as possible. Exceptions may apply, but should not be a common practice.</td></tr></TABLE>" 

add-content $report "</CENTER>"

Write-Host ('User Account Analysis Done. Found: ') -NoNewline
write-host $AllUsers -NoNewline -ForegroundColor Magenta
Write-Host ' User Accounts'

add-content $report "<BR><BR><BR><BR>"




######################################### COMPUTER ACCOUNTS #############################################

Add-Content $ADxRayLog ("ComputerDetailsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Computer Accounts data catcher")
Add-Content $ADxRayLog ("ComputerDetailsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Forest: "+$Forest)


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

Foreach ($Contr in $Forest.domains.PdcRoleOwner) 
    {

    Try{

    Add-Content $report "<tr>" 

    $PCDomain = $Contr.Domain

    $PCAll = dsquery * -filter sAMAccountType=805306369 -s $Contr -Attr OperatingSystem  -limit 0
    $PCAll =[System.Collections.ArrayList]$PCAll
    $PCAll.RemoveAt(0)

    $PCAllC = $PCAll.Count
    $PCServer = ($PCAll | where {$_ -like '* Server*'}).Count
    $PCWS = ($PCAll | where {$_ -notlike '* Server*'}).Count
    $PCServerUnsupp = ($PCAll | where {$_ -like '* Server*'} | Where {$_ -like '* NT*' -or $_ -like '*2000*' -or $_ -like '*2003*'}).Count
    $PCWSUnsupp = ($PCAll | where {$_ -notlike '* Server*'} | Where {$_ -like '* NT*' -or $_ -like '*2000*' -or $_ -like '*2000*' -or $_ -like '* 95*' -or $_ -like '* 98*' -or $_ -like '*XP*' -or $_ -like '* Vista*'}).Count


    Add-Content $ADxRayLog ("ComputerDetailsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Inventoring Computer Accounts in the Domain: "+$PCDomain)
    Add-Content $ADxRayLog ("ComputerDetailsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Total Computers found: "+$PCAllC)


    Add-Content $report "<td bgcolor='White' align=center>$PCDomain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$PCAllC</td>"         
    Add-Content $report "<td bgcolor='White' align=center>$PCWS</td>"
    Add-Content $report "<td bgcolor='White' align=center>$PCServer</td>"
    $ScoreLimit ++               
    if ($PCWSUnsupp -eq '' -or $PCWSUnsupp -eq 0) 
        {
            $ScoreCount ++
            Add-Content $report "<td bgcolor= 'Lime' align=center>0</td>"
        }
     else 
        { 
           Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$PCWSUnsupp</font></td>" 
        }
    $ScoreLimit ++
    if ($PCServerUnsupp -eq '' -or $PCServerUnsupp -eq 0)  
        {
            $ScoreCount ++
            Add-Content $report "<td bgcolor= 'Lime' align=center>0</td>"
        }
    else 
        { 
          Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$PCServerUnsupp</font></td>" 
        }

    Add-Content $report "</tr>"
    }
Catch { 
Add-Content $ADxRayLog ("ComputerDetailsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors were found during the Computer Accounts Inventoring -------------")
Add-Content $ADxRayLog ("ComputerDetailsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - The following error ocurred during catcher: "+$_.Exception.Message)
}
    }

Add-Content $ADxRayLog ("ComputerDetailsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Computer Accounts Inventory finished")

Add-Content $ADxRayLog ("ComputerDetailsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - End of Computer Account phase.")

Add-content $report  "</table>" 

add-content $report "<BR><BR>"

add-content $report "<TABLE BORDER=0 WIDTH=95%><tr><td>Those counters present a list of total Windows Servers and Workstations, total number of Windows Servers and Workstations that are enabled and have unsupported Operating Systems.</td></tr></TABLE>"  

add-content $report "</CENTER>"

Write-Host ('Computer Account Analysis Done. Found: ') -NoNewline
write-host $PCAllC -NoNewline -ForegroundColor Magenta
Write-Host ' Computer Accounts'

add-content $report "<BR><BR><BR><BR><BR><BR>"


######################################### GROUPS HEADER #############################################

add-content $report  "<table width='100%' border='0'>" 
add-content $report  "<tr bgcolor='White'>" 
add-content $report  "<td colspan='7' height='70' align='center'>" 
add-content $report  "<font face='tahoma' color='#000000' size='62'>Groups<HR></font>" 
add-content $report  "</td>" 
add-content $report  "</tr>" 
add-content $report  "</table>" 

add-content $report "<TABLE BORDER=0 WIDTH=95%><tr><td>This section will verify the number of members in critical administration groups in the Forest and Domain and will alert for every group with more than 30 members (including Users, Computers and other Groups).</td></tr></TABLE>"  

add-content $report "<BR><BR><BR><BR><BR><BR>"

######################################### GROUPS #############################################

Add-Content $ADxRayLog ("GroupsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Groups data catcher")
Add-Content $ADxRayLog ("GroupsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Forest: "+$Forest)


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

Foreach ($Contr in $Forest.domains.PdcRoleOwner) 
    {
    Try{
        Foreach ($gp in $Groups)
            {
            $temp = ('(&(objectclass=group)(sAMAccountName='+$gp+'))')
            $GpTemp = 0
            $GpTemp = (dsquery * -filter $temp -s $Contr -Attr member -limit 0)
            if ($GpTemp.split(';').count -gt 3)
                {
                    $GCounter = (($GpTemp -split(';')).Count - 2)
                    $GDomain = $Contr.Domain
                    $GName = $gp
                    Add-Content $report "<tr>"
                    Add-Content $report "<td bgcolor='White' align=center>$GDomain</td>" 
                    Add-Content $report "<td bgcolor='White' align=center>$GName</td>" 

                    Add-Content $ADxRayLog ("GroupsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Inventoring Group: "+$GName)
                    Add-Content $ADxRayLog ("GroupsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Total members found: "+$GCounter)

                    if ($GCounter -ge 5) 
                        {
                            $ScoreLimit ++
                            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GCounter</font></td>"
                        }
                    else 
                        { 
                            Add-Content $report "<td bgcolor='White' align=center>$GCounter</td>" 
                        } 
                   
                }
            if ($GpTemp.split(';').count -le 3)
                {
                    $GCounter = $GpTemp | where {$_ -like '*DC*'}
                    $GCounter = $GCounter.Count 
                    $GDomain = $Contr.Domain
                    $GName = $gp
                    Add-Content $report "<tr>"
                    Add-Content $report "<td bgcolor='White' align=center>$GDomain</td>" 
                    Add-Content $report "<td bgcolor='White' align=center>$GName</td>" 

                    Add-Content $ADxRayLog ("GroupsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Inventoring Group: "+$GName)
                    Add-Content $ADxRayLog ("GroupsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Total members found: "+$GCounter)

                    Add-Content $report "<td bgcolor='White' align=center>$GCounter</td>" 
                }
            Add-Content $report "</tr>"
            } 
            }
Catch { 
Add-Content $ADxRayLog ("GroupsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors were found during the Domain Groups Inventoring -------------")
Add-Content $ADxRayLog ("GroupsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - The following error ocurred during catcher: "+$_.Exception.Message)
}
    }

Add-Content $ADxRayLog ("GroupsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Domain Groups Inventory finished")


Add-content $report  "</table>"

add-content $report "<BR><BR>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Having far too many users with more than necessary permissions may result in serius security breaches. Make sure only the very necessary user accounts are present in those groups, unautohorized users may cause big damage. And remember to review the <a href='https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory'>Best Practices for Securing Active Directory</a>. And specialy '<a href='https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models'>Implementing Least-Privilege Administrative Models</a>'.</td></tr></TABLE>" 

add-content $report "</CENTER>"

add-content $report "<BR><BR><BR><BR>"

######################################### EMPTY GROUPS #############################################

Add-Content $ADxRayLog ("GroupsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Empty Groups data catcher")


add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>Active Directory Groups Overview</h3>" 
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
Foreach ($Contr in $Forest.domains.PdcRoleOwner) 
    {
    Try{
        $GroupsMembers = @()
        
        $PCDomain = $Contr.Domain
        $GroupAll = dsquery * -filter objectclass=group -s $Contr -Attr member -limit 0
        $Counter = @()
        Foreach ($gp in $GroupAll)
            {
                $Counter += (($gp -split(';')).Count - 1)
            }
        $GroupTotal = $Counter.Count
        $GroupLarge = ($Counter | where {$_ -ge 50}).Count
        $GroupEmpty = ($Counter | where {$_ -eq 0}).Count
        $GroupAve = ($Counter | Measure-Object -Average).Average
        
        Add-Content $report "<tr>" 

        Add-Content $report "<td bgcolor='White' align=center>$PCDomain</td>" 
        Add-Content $report "<td bgcolor='White' align=center>$GroupTotal</td>" 

        Add-Content $ADxRayLog ("GroupsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Inventoring Empty Groups in the Domain: "+$PCDomain)
        Add-Content $ADxRayLog ("GroupsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Total Empty Groups found: "+$GroupEmpty)
        $ScoreLimit ++
        if ($GroupLarge -gt 30) 
            {
                Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GroupLarge</font></td>"
            }
        else 
            {
                $ScoreCount ++ 
                Add-Content $report "<td bgcolor= 'Lime' align=center> $GroupLarge</td>" 
            }
        $ScoreLimit ++
        if ($GroupEmpty -gt 20) 
            {
                Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GroupEmpty</font></td>"
            }
        else 
            {
                $ScoreCount ++ 
                Add-Content $report "<td bgcolor= 'Lime' align=center>$GroupEmpty</td>" 
            }
        $ScoreLimit ++
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
                $ScoreCount ++
                $GroupAve = $GroupAve.tostring("#.##") 
                Add-Content $report "<td bgcolor='Lime' align=center>$GroupAve</td>" 
            }


        Add-Content $report "<tr>"
        }
Catch { 
Add-Content $ADxRayLog ("GroupsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors were found during the Empty Domain Groups Inventoring -------------")
Add-Content $ADxRayLog ("GroupsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - The following error ocurred during catcher: "+$_.Exception.Message)
}
    }

Add-Content $ADxRayLog ("GroupsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Empty Domain Groups Inventory finished")

Add-Content $ADxRayLog ("GroupsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - End of Groups phase.")

Add-content $report  "</table>"

add-content $report "<BR><BR>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Having fair number of groups is not also a good practice, it's vital to ensure an easier and 'clean' management of Active Directory, usually don't make sense have more groups than users or groups too small. And remember to review the <a href='https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory'>Best Practices for Securing Active Directory</a>. And specialy '<a href='https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models'>Implementing Least-Privilege Administrative Models</a>'.</td></tr></TABLE>" 

add-content $report "</CENTER>"

Write-Host ('AD Groups Analysis Done. Found: ') -NoNewline
write-host $GroupTotal -NoNewline -ForegroundColor Magenta
Write-Host ' Groups'

add-content $report "<BR><BR><BR><BR><BR><BR>"

######################################### GPO HEADER #############################################

write-host 'Starting GPO Analysis..'

add-content $report  "<table width='100%' border='0'>" 
add-content $report  "<tr bgcolor='White'>" 
add-content $report  "<td colspan='7' height='70' align='center'>" 
add-content $report  "<font face='tahoma' color='#000000' size='62'>Group Policy Objects<HR></font>" 
add-content $report  "</td>" 
add-content $report  "</tr>" 
add-content $report  "</table>" 

add-content $report "<TABLE BORDER=0 WIDTH=95%><tr><td>This section will verify the avarage status of Group Policies in the Forest and Domain and will alert for every group policy with <B>too many configurations</B>, <B>withou any configuration</b> at all, or <B>not linked to any OU</B>.</td></tr></TABLE>"  

add-content $report "<BR><BR><BR><BR><BR><BR>"


######################################### GPOs #############################################

Add-Content $ADxRayLog ("GPOsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting Group Policy Objects data catcher")
Add-Content $ADxRayLog ("GPOsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Forest: "+$Forest)


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
Add-Content $report  "<td width='5%' align='center'><B>Too Many Settings</B></td>" 
 

Add-Content $report "</tr>" 

Foreach ($Contr in $Forest.domains.PdcRoleOwner) 
    {
        Try{
                $gp1 = @()
                $GpoC = @()
                $Gpo = Get-GPO -All -Server $Contr
                $Ous = Get-ADOrganizationalUnit -Filter * -Server $Contr
                $GPEmpt = ($Gpo | where {$_.User.DSVersion -eq 0 -and $_.User.SysvolVersion -eq 0 -and $_.Computer.DSVersion -eq 0 -and $_.Computer.SysvolVersion -eq 0}).Count
                $GPBIG = ($Gpo | Where {(($_.User.DSlVersion) + ($_.Computer.DSVersion)) -ge 1000}).Count
                Foreach ($ou in $Ous)
                    {
                        $gp1 += (Get-GPInheritance -Target $ou).GpoLinks 
                    }
                Foreach ($gp2 in $Gpo)
                    {
                        $GpoC += Get-GPO -Name $gp2.DisplayName | where {$_.DisplayName -notin $gp1.DisplayName -and $_.DisplayName -ne 'Default Domain Policy'}
                    }
                $Domain = $Contr.Domain
                $GpoAll = $Gpo.Count
                $GpoC2 = $GpoC.Count

                Add-Content $report "<tr>"

                Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
                Add-Content $report "<td bgcolor='White' align=center>$GpoAll</td>" 

                Add-Content $ADxRayLog ("GPOsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Inventoring Group Policies in the Domain: "+$Domain)
                Add-Content $ADxRayLog ("GPOsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Total GPOs found: "+$GpoAll)
                $ScoreLimit ++
                if ($GpoC2 -ge 1) 
                    {
                        Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GpoC2 GPOs</font></td>"
                    }
                else 
                    {
                        $ScoreCount ++ 
                        Add-Content $report "<td bgcolor= 'Lime' align=center>$GpoC2 GPOs</td>" 
                    }
                $ScoreLimit ++
                if ($GPEmpt -ge 1) 
                    {
                        Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GPEmpt GPOs</font></td>"
                    }
                else 
                    {
                        $ScoreCount ++ 
                        Add-Content $report "<td bgcolor= 'Lime' align=center>$GPEmpt GPOs</td>" 
                    }
                $ScoreLimit ++
                if ($GPBIG -ge 1) 
                    {
                        Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GPBIG GPOs</font></td>"
                    }
                else 
                    {
                        $ScoreCount ++ 
                        Add-Content $report "<td bgcolor= 'Lime' align=center>$GPBIG GPOs</td>" 
                    }

                Add-Content $report "</tr>"
                }
Catch { 
Add-Content $ADxRayLog ("GPOsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors were found during the GPOs Inventoring -------------")
Add-Content $ADxRayLog ("GPOsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - The following error ocurred during catcher: "+$_.Exception.Message)
}
    }

Add-Content $ADxRayLog ("GPOsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - GPOs Inventory finished")


Add-content $report  "</table>" 

add-content $report "<BR><BR>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Group Policy represent an important part of Active Directory management (without mention its impact on Servers and Workstation). Make sure GPO conflicts are avoided always as possible, also take GPO backups at a regular basis (<a href='https://docs.microsoft.com/en-us/powershell/module/grouppolicy/backup-gpo?view=win10-ps'>Backup-GPO</a>).</td></tr></TABLE>" 

add-content $report "</CENTER>"

Write-Host ('Found: ') -NoNewline
write-host $GPOall -NoNewline -ForegroundColor Magenta
Write-Host ' GPOs. Starting the Analyse them' 

add-content $report "<BR><BR><BR><BR>"


######################################### GPOs WITHOUT LINK #############################################


Add-Content $ADxRayLog ("GPOsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Starting GPOs Without Link catcher")
Add-Content $ADxRayLog ("GPOsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Forest: "+$Forest)


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

Foreach ($Contr in $Forest.domains.PdcRoleOwner) 
    {
    Try{
                $Ous = Get-ADOrganizationalUnit -Filter * -Server $Contr
                $gp1 = @()
                Foreach ($ou in $Ous)
                    {
                        $gp1 += (Get-GPInheritance -Target $ou).GpoLinks 
                    }
                $Gpos = Get-GPO -All -Server $Contr
                $GposNoLink = Get-GPO -all -Server $Contr | where {$_.DisplayName -notin $gp1.DisplayName -and $_.DisplayName -ne 'Default Domain Policy' -and $_.DisplayName -ne 'Default Domain Controllers Policy'}
                Foreach ($GPO in $Gpos)
                    {
                        
                        $GpoName = $Gpo.DisplayName
                        $GpoUserADVer = $Gpo.User.DSVersion
                        $GpoCompADVer = $Gpo.Computer.DSVersion
                        $GpoModDate =  $Gpo.ModificationTime

                        Add-Content $ADxRayLog ("GPOsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - Inventoring the Following GPO: "+$GpoName)

                        if ($GpoUserADVer -eq 0 -and $GpoCompADVer -eq 0 -and $Gpo.id -in $GposNoLink.id)
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
                        elseif ($Gpo.id -in $GposNoLink.id)
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
Add-Content $ADxRayLog ("GPOsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - ------------- Errors were found during the GPO Inventoring -------------")
Add-Content $ADxRayLog ("GPOsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - The following error ocurred during catcher: "+$_.Exception.Message)
}
            }
 
Add-Content $ADxRayLog ("GPOsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - GPOs without link Inventory finished")

Add-Content $ADxRayLog ("GPOsLog - "+(get-date -Format 'MM-dd-yyyy  HH:mm:ss')+" - End of log file")

Add-content $report  "</table>" 

add-content $report "<BR><BR>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Make sure to investigate and solve problems listed here, Having too many unsued GPOs may impact your Active Directory management effort.</td></tr></TABLE>" 

add-content $report "</CENTER>"

add-content $report "<BR><BR><BR><BR>"

##################################### VERSION CONTROL #######################################

write-host 'Starting ADxRay Version Validation..'

$VerValid = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Merola132/ADxRay/master/Docs/VersionControl" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -TimeoutSec 5
$ScoreLimit ++
if ($VerValid.StatusCode -eq 200) 
    {
        if (($VerValid.Content[0]+$VerValid.Content[1]+$VerValid.Content[2]) -eq $Ver) 
            {
                $ScoreCount ++
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


######################################### INDEX #############################################

}
$Measure = $Runtime.Totalminutes.ToString('#######.##')

$index = Get-Content $report

$Index[23] = "<TABLE BORDER=0 WIDTH=20% align='right'><tr><td align='right'><font face='verdana' color='#000000' size='4'> Execution: $Measure Minutes<HR></font></td></tr></TABLE>"

$index | out-file $report

sleep 10

######################################### CLOSING #############################################

Add-Content $report "</tr>"
Add-content $report  "</table>" 
add-content $report "<BR><A HREF='#top'>Back to the top</A><BR>"
add-content $report "<BR><TABLE BORDER='1' CELLPADDING='5'><TR><TD BGCOLOR='Silver'><A NAME='Disclaimer'><B>Disclaimer:</B></A> This report was generated using the ADxRay Powershell Script. The information provided in this report is provided 'as-is' and is intended for information purposes only. The information present at the script is licensed 'as-is'. You bear the risk of using it. The contributors give no express warranties, guarantees or conditions. You may have additional consumer rights under your local laws which this license cannot change. To the extent permitted under your local laws, the contributors exclude the implied warranties of merchantability, fitness for a particular purpose and non-infringement. Any feedback or improvements feel free to email me at: <a href='mailto:merola@outlook.com?Subject=ADxRay%20feedback' target='_top'>Claudio Merola</a></TD></TR></TABLE>"
add-content $report "<BR><TABLE BORDER='1' CELLPADDING='5'><TR><TD BGCOLOR='Silver'><A NAME='More'><B>More:</B></A> If you wish to have a better inventory and reporting regarding your Active Directory environment, Get in touch with your Microsoft representative to run an On-Demand Assessment in your Active Directory environment. On-Demand Assessment will give you a deep view and understanding of every single issue existing in the environment. More details at: <a href='https://docs.microsoft.com/en-us/services-hub/health/'>Services Hub On-Demand Assessments</a></TD></TR></TABLE>"
Add-Content $report "</body>" 
Add-Content $report "</html>" 

Invoke-Item $report























 
