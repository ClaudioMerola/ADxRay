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


$Runtime = Measure-Command -Expression {
if ((Test-Path -Path C:\ADHC -PathType Container) -eq $false) {New-Item -Type Directory -Force -Path C:\ADHC}

$report = "C:\ADHC\ADHC_Report.htm" 
if ((test-path $report) -eq $false) {new-item $report -Type file -Force}
Clear-Content $report 

$Forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()

Add-Content $report "<html>" 
Add-Content $report "<head>" 
Add-Content $report "<meta http-equiv='Content-Type' content='text/html; charset=iso-8859-1'>" 
Add-Content $report "<title>ADReport - $Forest</title>"
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
add-content $report  "<font face='tahoma' color='#0000FF' size='75'><strong>PFE's Active Directory Report</strong></font>" 
add-content $report  "</td>"  
add-content $report  "</tr>" 
add-content $report  "</table>"
 

######################################### INDEX #############################################


<# Index is made close to the end of the script. (It has to be done this way to supply index with variables of error counts).
Close to the end it reads the report file and replaces thoses <BR> with the real index. If you need to add more items to the index sim


#>

add-content $report  "<TABLE BORDER=0 WIDTH=90%><tr><td><font face='verdana' size='1'>This Report is intended to help network administrators and contractors to get a better understanding and overview of the actual status and health of their Active Directory Forest, Domains, Domain Controllers, DNS Servers and Active Directory objects such as User Accounts, Computer Accounts, Groups and Group Policies. This report has been tested in several Active Directory topologies and environments without further problems or impacts in the server or environment´s performance. If you however experience some sort of problem while running this script/report. Feel free to send that feedback and we will help to investigate as soon as possible (feedback information’s are presented at the end of this report). Thanks for using.</font></td></tr></TABLE>"
add-content $report "<BR>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"

######################################### FOREST HEADER #############################################

add-content $report "<div id='ForestHeader'></div>"

add-content $report  "<table width='100%' border='0'>" 
add-content $report  "<tr bgcolor='White'>" 
add-content $report  "<td colspan='7' height='70' align='center'>" 
add-content $report  "<font face='verdana' color='#000000' size='62'>Active Directory Forest<HR></font>" 
add-content $report  "</td>" 
add-content $report  "</tr>" 
add-content $report  "</table>" 

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>This section is intended to give an overall view of the <B>Active Directory Forest</B>, as so as the <B>Active Directory Domains</B> and <B>Domain Controllers</B> and configured <B>Trusts</B> between Active Directory Domains and others Active Directory Forests.</td></tr></TABLE>" 

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"


######################################### FOREST #############################################


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
$IndexForest0 = 0
    if ($ForeMode -like '*NT*' -or $ForeMode -like '*2000*' -or $ForeMode -like '*2003*')
        {
            $IndexForest0 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$ForeMode</font></td>" 
        }
    elseif ($ForeMode -like '*2008*' -and $ForeMode -notlike '*2008R2*') 
        {
            $IndexForest0 ++
            Add-Content $report "<td bgcolor= 'Yellow' align=center>$ForeMode</td>" 
        }
    elseif ($ForeMode -like '*2012*' -or $ForeMode -like '*2016*') 
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
            $IndexForest0 ++
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
Add-content $report  "</table>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>" 


######################################### TRUST #############################################

add-content $report "<div id='TrustOverview'></div>"

add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>Active Directory Trusts View ($Forest)</h3>" 
add-content $report  "</CENTER>"
add-content $report "<BR>"
 

$Trust1 = Get-ADtrust -Filter * -Server $Forest.SchemaRoleOwner

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
    
        Add-Content $report "<td bgcolor='White' align=center>$T3Source</td>" 
        Add-Content $report "<td bgcolor='White' align=center>$T3Target</td>" 
        Add-Content $report "<td bgcolor='White' align=center>$T3Dir</td>" 
        Add-Content $report "<td bgcolor='White' align=center>$T3Trans</B></td>" 
        Add-Content $report "<td bgcolor='White' align=center>$T3Intra</td>" 
        Add-Content $report "<td bgcolor='White' align=center>$T3SIDFil</td>" 
        Add-Content $report "</tr>" 
    }
 
Add-content $report  "</table>"


add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"




######################################### DOMAIN #############################################

add-content $report "<div id='DomainOverview'></div>"

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
Add-Content $report  "<td width='10%' align='center'><B>Domain Computer Container</B></td>"
Add-Content $report  "<td width='10%' align='center'><B>Domain User Container</B></td>" 

 
Add-Content $report "</tr>" 

Foreach ($Domain0 in $Forest.Domains.Name)
    {
    $Domain1 = Get-ADDomain -Identity $Domain0

    Add-Content $report "<tr>" 
    
    $D2Name = $Domain1.DNSRoot
    $D2Parent = $Domain0.ParentDomain
    $D2Child = $Domain1.ChildDomains
    $D2Mode = $Domain1.DomainMode
    $D2CompCont = $Domain1.ComputersContainer
    $D2UserCont = $Domain1.UsersContainer
    $IndexDomain0 = 0
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
    Add-Content $report "<td bgcolor='White' align=center>$ForeName</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$D2Name</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$D2Parent</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$D2Child</B></td>" 
    if ($D2Mode -like '*NT*' -or $D2Mode -like '*2000*' -or $D2Mode -like '*2003*')
        {
            $IndexDomain0 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$D2Mode</font></td>" 
        }
    elseif ($D2Mode -like '*2008*' -and $D2Mode -notlike '*2008R2*') 
        { 
            $IndexDomain0 ++
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
    Add-Content $report "<td bgcolor='White' align=center>$D2CompCont</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$D2UserCont</td>" 

    }

Add-Content $report "</tr>" 
 
Add-content $report  "</table>"

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report "</CENTER>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Domain's design must be as clear as possible and always based on best practices. Remember to consult <a href='https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/creating-a-site-design'>Creating a Site Design</a> and <a href='https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/determining-the-number-of-domains-required'>Determining the Number of Domains Required</a> before adding any new Domains in the topology.</td></tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"


######################################### DC #############################################

add-content $report "<div id='DCOverview'></div>"

add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>Active Directory Domain Controllers View ($Forest)</h3>" 
add-content $report  "</CENTER>"
add-content $report "<BR>"
 
add-content $report  "<table width='90%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='5%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>Enabled</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>DNS Service</B></td>" 
Add-Content $report  "<td width='8%' align='center'><B>IPV4 Address</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>Global Catalog</B></td>" 
Add-Content $report  "<td width='15%' align='center'><B>Operating System</B></td>" 
Add-Content $report  "<td width='5%' align='center'><B>Operating System Build</B></td>"
Add-Content $report  "<td width='10%' align='center'><B>FSMO</B></td>"
Add-Content $report  "<td width='10%' align='center'><B>Site</B></td>"
 
Add-Content $report "</tr>" 

$IndexDC0 = 0

$DCs = $Forest.domains | ForEach-Object {$_.DomainControllers} | ForEach-Object {$_.Name} 

foreach ($DC in $DCs)
    {
    Add-Content $report "<tr>"

    $DCD = Get-ADDomainController -Server $DC 
    $DCD = $DCD | Sort-Object

    $DCDNSService = start-job -scriptblock {get-service -ComputerName $($args[0]) -Name "DNS" -ErrorAction SilentlyContinue} -ArgumentList $DC
    wait-job -Job $DCDNSService -Timeout 20
    $DCDNSServiceStatus = (receive-job -job $DCDNSService).Status

    $Domain = $DCD.Domain
    $DCHostName = $DCD.Hostname
    $DCEnabled = $DCD.Enabled
    $DCIP = $DCD.IPv4Address
    $DCGC = $DCD.IsGlobalCatalog
    $DCOS = $DCD.OperatingSystem
    $DCOSD = $DCD.OperatingSystemVersion
    $FSMO = $DCD.OperationMasterRoles 
    $Site = $DCD.Site

    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DCHostname</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DCEnabled</td>" 

    if ($DCDNSServiceStatus -eq 'Running')
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>$DCDNSServiceStatus</td>"
        }
    elseif ($DCDNSServiceStatus -eq 'Stopped')
        {
            $IndexDC0 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$DCDNSServiceStatus</font></td>" 
        }
    else
        {
            $IndexDC0 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Irresponsible</font></td>" 
        }
    Add-Content $report "<td bgcolor='White' align=center>$DCIP</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DCGC</td>" 

        if ($DCOS -like '* NT*' -or $DCOS -like '* 2000*' -or $DCOS -like '* 2003*')
        {
            $IndexDC0 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$DCOS</font></td>" 
        }
    elseif ($DCOS -like '* 2008*' -or $DCOS -like '* 2008 R2*') 
        { 
            $IndexDC0 ++
            Add-Content $report "<td bgcolor= 'Yellow' align=center>$DCOS</td>" 
        }
    elseif ($DCOS -like '* 2012*' -or $DCOS -like '* 2016*') 
        { 
            Add-Content $report "<td bgcolor= 'Lime' align=center>$DCOS</td>" 
        }
    else
        {
            Add-Content $report "<td bgcolor='White' align=center>$DCOS</td>" 
        }
     
    Add-Content $report "<td bgcolor='White' align=center>$DCOSD</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$FSMO</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$Site</td>" 
    }
Add-Content $report "</tr>" 
 
Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Many Domain Controllers does not represent a problem. But using an oversized topology might increase the administrative effort and decrease the security of the environment as every writable Domain Controller have a full copy of every user account along with their password. Make sure to keep a reasonable number of Domain Controllers and keep they secured as possible.</td></tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"


######################################### DCs HEADER #############################################


add-content $report "<div id='DCHealth'></div>"


add-content $report  "<table width='100%' border='0'>" 
add-content $report  "<tr bgcolor='White'>" 
add-content $report  "<td colspan='7' height='70' align='center'>" 
add-content $report  "<font face='verdana' color='#000000' size='62'>Domain Controller Health<HR></font>" 
add-content $report  "</td>" 
add-content $report  "</tr>" 
add-content $report  "</table>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>This section will give a detailed view of the Domain Controller's health. With tests and validations based on <B>DCDiag</B> tool and should be enough to give a deep status of Domain Controllers.</td></tr></TABLE>" 



######################################### Advertising ############################################


add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"

add-content $report "<div id='Advertising'></div>"

add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>Advertising Validation</h3>" 
add-content $report  "</CENTER>"
add-content $report  "<BR>"
 
add-content $report  "<table width='80%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Connectivity</B></td>" 
Add-Content $report  "<td width='20%' align='center'><B>Advertising</B></td>" 

 
Add-Content $report "</tr>" 

$DCs = $Forest.domains | ForEach-Object {$_.DomainControllers} | ForEach-Object {$_.Name} 
$IndexDC2 = 0
foreach ($DC in $DCs)
    {
    Add-Content $report "<tr>"

    $DCDiag = start-job -scriptblock {dcdiag /test:Advertising /s:$($args[0])} -ArgumentList $DC
    wait-job -Job $DCDiag -Timeout 20
    $DCDiag = receive-job -job $DCDiag


    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DC</td>" 



    if (($DCDiag | Select-String -Pattern 'passed test Connectivity').Count -eq $true)
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Ping, LDAP and RPC Connectivity Passed</td>"
        }
    else
        {
            $IndexDC2 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Connectivity test failed</font></td>" 
        }

    if (($DCDiag | Select-String -Pattern 'passed test Advertising').Count -eq $true)
        {
            $Pass = $DCDiag | Select-String -Pattern 'passed test Advertising'
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Pass</td>"
        }
    else
        {
            $IndexDC2 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Test failed</font></td>" 
        }

    }

Add-Content $report "</tr>" 
 
Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Checks whether each domain controller advertises itself in the roles that it should be capable of performing. This test fails if the Netlogon Service has stopped or failed to start. For more details regarding the tool, check '<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731968(v%3Dws.11)'>DCDiag</a>'.Also, verify '<a href='https://blogs.technet.microsoft.com/askds/2011/03/22/what-does-dcdiag-actually-do/'>What does DCDiag actually do</a>' for further understanding.</td></tr></TABLE>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Obs. Before the main test is made, the basic connectivity with the DC (DNS check, ICMP and RPC) is validated. This validation also includes LDAP binding (<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755809(v=ws.10)'>How Active Directory Searches Work</a>).</td></tr></TABLE>"

add-content $report  "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"



######################################### FSREvent ############################################


add-content $report "<div id='FSREvent'></div>"

add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>FrsEvent Validation</h3>" 
add-content $report  "</CENTER>"
add-content $report  "<BR>"
 
add-content $report  "<table width='80%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Connectivity</B></td>" 
Add-Content $report  "<td width='20%' align='center'><B>FSREvent</B></td>" 

 
Add-Content $report "</tr>" 

$DCs = $Forest.domains | ForEach-Object {$_.DomainControllers} | ForEach-Object {$_.Name} 
$IndexDC3 = 0
foreach ($DC in $DCs)
    {
    Add-Content $report "<tr>"

    $DCDiag = start-job -scriptblock {dcdiag /test:FSREvent /s:$($args[0])} -ArgumentList $DC
    wait-job -Job $DCDiag -Timeout 20
    $DCDiag = receive-job -job $DCDiag


    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DC</td>" 



    if (($DCDiag | Select-String -Pattern 'passed test Connectivity').Count -eq $true)
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Ping, LDAP and RPC Connectivity Passed</td>"
        }
    else
        {
            $IndexDC3 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Connectivity test failed</font></td>" 
        }

    if (($DCDiag | Select-String -Pattern 'passed test FrsEvent').Count -eq $true)
        {
            $Pass = $DCDiag | Select-String -Pattern 'passed test FrsEvent'
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Pass</td>"
        }
    else
        {
            $IndexDC3 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Test failed</font></td>" 
        }

    }

Add-Content $report "</tr>" 
 
Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Checks to see if there are errors in the file replication system (Failing replication of the SYSVOL share can cause policy problems). For more details regarding the tool, check '<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731968(v%3Dws.11)'>DCDiag</a>'.Also, verify '<a href='https://blogs.technet.microsoft.com/askds/2011/03/22/what-does-dcdiag-actually-do/'>What does DCDiag actually do</a>' for further understanding.</td></tr></TABLE>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Obs. Before the main test is made, the basic connectivity with the DC (DNS check, ICMP and RPC) is validated. This validation also includes LDAP binding (<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755809(v=ws.10)'>How Active Directory Searches Work</a>).</td></tr></TABLE>"

add-content $report  "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"


######################################### DFSREvent ############################################


add-content $report "<div id='DFSREvent'></div>"

add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>DFSREvent Validation</h3>" 
add-content $report  "</CENTER>"
add-content $report  "<BR>"
 
add-content $report  "<table width='80%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Connectivity</B></td>" 
Add-Content $report  "<td width='20%' align='center'><B>DFSREvent</B></td>" 

 
Add-Content $report "</tr>" 

$DCs = $Forest.domains | ForEach-Object {$_.DomainControllers} | ForEach-Object {$_.Name} 
$IndexDC4 = 0
foreach ($DC in $DCs)
    {
    Add-Content $report "<tr>"

    $DCDiag = start-job -scriptblock {dcdiag /test:DFSREvent /s:$($args[0])} -ArgumentList $DC
    wait-job -Job $DCDiag -Timeout 20
    $DCDiag = receive-job -job $DCDiag


    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DC</td>" 



    if (($DCDiag | Select-String -Pattern 'passed test Connectivity').Count -eq $true)
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Ping, LDAP and RPC Connectivity Passed</td>"
        }
    else
        {
            $IndexDC4 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Connectivity test failed</font></td>" 
        }

    if (($DCDiag | Select-String -Pattern 'passed test DFSREvent').Count -eq $true)
        {
            $Pass = $DCDiag | Select-String -Pattern 'passed test DFSREvent'
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Pass</td>"
        }
    else
        {
            $IndexDC4 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Test failed</font></td>" 
        }

    }

Add-Content $report "</tr>" 
 
Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>This test validates the Distributed File System Replication service’s health by reading DFSR event log warning and error entries from the past 24 hours. It’s possible this service won’t be running or installed on Windows Server 2008 if SYSVOL is still using FRS; on Windows Server 2008 R2 the service is always present on DCs. While this ostensibly tests DFSR-enabled SYSVOL, any errors within custom DFSR replication groups would also appear here. For more details regarding the tool, check '<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731968(v%3Dws.11)'>DCDiag</a>'.Also, verify '<a href='https://blogs.technet.microsoft.com/askds/2011/03/22/what-does-dcdiag-actually-do/'>What does DCDiag actually do</a>' for further understanding.</td></tr></TABLE>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Obs. Before the main test is made, the basic connectivity with the DC (DNS check, ICMP and RPC) is validated. This validation also includes LDAP binding (<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755809(v=ws.10)'>How Active Directory Searches Work</a>).</td></tr></TABLE>"

add-content $report  "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"



######################################### SysVolCheck ############################################


add-content $report "<div id='SysVolCheck'></div>"

add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>SysVolCheck Validation</h3>" 
add-content $report  "</CENTER>"
add-content $report  "<BR>"
 
add-content $report  "<table width='80%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Connectivity</B></td>" 
Add-Content $report  "<td width='20%' align='center'><B>SysVolCheck</B></td>" 

 
Add-Content $report "</tr>" 

$DCs = $Forest.domains | ForEach-Object {$_.DomainControllers} | ForEach-Object {$_.Name} 
$IndexDC5 = 0
foreach ($DC in $DCs)
    {
    Add-Content $report "<tr>"

    $DCDiag = start-job -scriptblock {dcdiag /test:SysVolCheck /s:$($args[0])} -ArgumentList $DC
    wait-job -Job $DCDiag -Timeout 20
    $DCDiag = receive-job -job $DCDiag


    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DC</td>" 



    if (($DCDiag | Select-String -Pattern 'passed test Connectivity').Count -eq $true)
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Ping, LDAP and RPC Connectivity Passed</td>"
        }
    else
        {
            $IndexDC5 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Connectivity test failed</font></td>" 
        }

    if (($DCDiag | Select-String -Pattern 'passed test SysVolCheck').Count -eq $true)
        {
            $Pass = $DCDiag | Select-String -Pattern 'passed test SysVolCheck'
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Pass</td>"
        }
    else
        {
            $IndexDC5 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Test failed</font></td>" 
        }

    }

Add-Content $report "</tr>" 
 
Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>This test reads the DCs Netlogon SysvolReady registry key to validate that SYSVOL is being advertised. The test uses RPC over SMB (through a named pipe to WinReg). For more details regarding the tool, check '<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731968(v%3Dws.11)'>DCDiag</a>'.Also, verify '<a href='https://blogs.technet.microsoft.com/askds/2011/03/22/what-does-dcdiag-actually-do/'>What does DCDiag actually do</a>' for further understanding.</td></tr></TABLE>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Obs. Before the main test is made, the basic connectivity with the DC (DNS check, ICMP and RPC) is validated. This validation also includes LDAP binding (<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755809(v=ws.10)'>How Active Directory Searches Work</a>).</td></tr></TABLE>"

add-content $report  "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"



######################################### KccEvent ############################################


add-content $report "<div id='KccEvent'></div>"

add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>KccEvent Validation</h3>" 
add-content $report  "</CENTER>"
add-content $report  "<BR>"
 
add-content $report  "<table width='80%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Connectivity</B></td>" 
Add-Content $report  "<td width='20%' align='center'><B>KccEvent</B></td>" 

 
Add-Content $report "</tr>" 

$DCs = $Forest.domains | ForEach-Object {$_.DomainControllers} | ForEach-Object {$_.Name} 
$IndexDC6 = 0
foreach ($DC in $DCs)
    {
    Add-Content $report "<tr>"

    $DCDiag = start-job -scriptblock {dcdiag /test:KccEvent /s:$($args[0])} -ArgumentList $DC
    wait-job -Job $DCDiag -Timeout 20
    $DCDiag = receive-job -job $DCDiag


    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DC</td>" 



    if (($DCDiag | Select-String -Pattern 'passed test Connectivity').Count -eq $true)
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Ping, LDAP and RPC Connectivity Passed</td>"
        }
    else
        {
            $IndexDC6 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Connectivity test failed</font></td>" 
        }

    if (($DCDiag | Select-String -Pattern 'passed test KccEvent').Count -eq $true)
        {
            $Pass = $DCDiag | Select-String -Pattern 'passed test KccEvent'
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Pass</td>"
        }
    else
        {
            $IndexDC6 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Test failed</font></td>" 
        }

    }

Add-Content $report "</tr>" 
 
Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>This test queries the <a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc731537(v=ws.10)#BKMK_2'>Knowledge Consistency Checker</a> on a DC for KCC errors and warnings generated in the Directory Services event log during the last 15 minutes. This 15 minute threshold is irrespective of the <a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc739941(v=ws.10)#w2k3tr_repup_tools_amfa'>Repl topology update period (secs)</a> registry value on the DC. For more details regarding the tool, check '<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731968(v%3Dws.11)'>DCDiag</a>'.Also, verify '<a href='https://blogs.technet.microsoft.com/askds/2011/03/22/what-does-dcdiag-actually-do/'>What does DCDiag actually do</a>' for further understanding.</td></tr></TABLE>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Obs. Before the main test is made, the basic connectivity with the DC (DNS check, ICMP and RPC) is validated. This validation also includes LDAP binding (<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755809(v=ws.10)'>How Active Directory Searches Work</a>).</td></tr></TABLE>"

add-content $report  "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"



######################################### KnowsOfRoleHolders ############################################


add-content $report "<div id='KnowsOfRoleHolders'></div>"

add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>KnowsOfRoleHolders Validation</h3>" 
add-content $report  "</CENTER>"
add-content $report  "<BR>"
 
add-content $report  "<table width='80%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Connectivity</B></td>" 
Add-Content $report  "<td width='20%' align='center'><B>KnowsOfRoleHolders</B></td>" 

 
Add-Content $report "</tr>" 

$DCs = $Forest.domains | ForEach-Object {$_.DomainControllers} | ForEach-Object {$_.Name} 
$IndexDC7 = 0
foreach ($DC in $DCs)
    {
    Add-Content $report "<tr>"

    $DCDiag = start-job -scriptblock {dcdiag /test:KnowsOfRoleHolders /s:$($args[0])} -ArgumentList $DC
    wait-job -Job $DCDiag -Timeout 20
    $DCDiag = receive-job -job $DCDiag


    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DC</td>" 



    if (($DCDiag | Select-String -Pattern 'passed test Connectivity').Count -eq $true)
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Ping, LDAP and RPC Connectivity Passed</td>"
        }
    else
        {
            $IndexDC7 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Connectivity test failed</font></td>" 
        }

    if (($DCDiag | Select-String -Pattern 'passed test KnowsOfRoleHolders').Count -eq $true)
        {
            $Pass = $DCDiag | Select-String -Pattern 'passed test KnowsOfRoleHolders'
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Pass</td>"
        }
    else
        {
            $IndexDC7 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Test failed</font></td>" 
        }

    }

Add-Content $report "</tr>" 
 
Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Checks whether the domain controller can contact the servers that hold the five operations master roles (also known as flexible single master operations or FSMO roles). For more details regarding the tool, check '<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731968(v%3Dws.11)'>DCDiag</a>'.Also, verify '<a href='https://blogs.technet.microsoft.com/askds/2011/03/22/what-does-dcdiag-actually-do/'>What does DCDiag actually do</a>' for further understanding.</td></tr></TABLE>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Obs. Before the main test is made, the basic connectivity with the DC (DNS check, ICMP and RPC) is validated. This validation also includes LDAP binding (<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755809(v=ws.10)'>How Active Directory Searches Work</a>).</td></tr></TABLE>"

add-content $report  "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"


######################################### MachineAccount ############################################


add-content $report "<div id='MachineAccount'></div>"

add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>MachineAccount Validation</h3>" 
add-content $report  "</CENTER>"
add-content $report  "<BR>"
 
add-content $report  "<table width='80%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Connectivity</B></td>" 
Add-Content $report  "<td width='20%' align='center'><B>MachineAccount</B></td>" 

 
Add-Content $report "</tr>" 

$DCs = $Forest.domains | ForEach-Object {$_.DomainControllers} | ForEach-Object {$_.Name} 
$IndexDC8 = 0
foreach ($DC in $DCs)
    {
    Add-Content $report "<tr>"

    $DCDiag = start-job -scriptblock {dcdiag /test:MachineAccount /s:$($args[0])} -ArgumentList $DC
    wait-job -Job $DCDiag -Timeout 20
    $DCDiag = receive-job -job $DCDiag


    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DC</td>" 



    if (($DCDiag | Select-String -Pattern 'passed test Connectivity').Count -eq $true)
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Ping, LDAP and RPC Connectivity Passed</td>"
        }
    else
        {
            $IndexDC8 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Connectivity test failed</font></td>" 
        }

    if (($DCDiag | Select-String -Pattern 'passed test MachineAccount').Count -eq $true)
        {
            $Pass = $DCDiag | Select-String -Pattern 'passed test MachineAccount'
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Pass</td>"
        }
    else
        {
            $IndexDC8 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Test failed</font></td>" 
        }

    }

Add-Content $report "</tr>" 
 
Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Checks whether the machine account has properly registered and that the services are advertised. For more details regarding the tool, check '<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731968(v%3Dws.11)'>DCDiag</a>'.Also, verify '<a href='https://blogs.technet.microsoft.com/askds/2011/03/22/what-does-dcdiag-actually-do/'>What does DCDiag actually do</a>' for further understanding.</td></tr></TABLE>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Obs. Before the main test is made, the basic connectivity with the DC (DNS check, ICMP and RPC) is validated. This validation also includes LDAP binding (<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755809(v=ws.10)'>How Active Directory Searches Work</a>).</td></tr></TABLE>"

add-content $report  "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"


######################################### NCSecDesc ############################################


add-content $report "<div id='NCSecDesc'></div>"

add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>NCSecDesc Validation</h3>" 
add-content $report  "</CENTER>"
add-content $report  "<BR>"
 
add-content $report  "<table width='80%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Connectivity</B></td>" 
Add-Content $report  "<td width='20%' align='center'><B>NCSecDesc</B></td>" 

 
Add-Content $report "</tr>" 

$DCs = $Forest.domains | ForEach-Object {$_.DomainControllers} | ForEach-Object {$_.Name} 
$IndexDC9 = 0
foreach ($DC in $DCs)
    {
    Add-Content $report "<tr>"

    $DCDiag = start-job -scriptblock {dcdiag /test:NCSecDesc /s:$($args[0])} -ArgumentList $DC
    wait-job -Job $DCDiag -Timeout 20
    $DCDiag = receive-job -job $DCDiag


    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DC</td>" 



    if (($DCDiag | Select-String -Pattern 'passed test Connectivity').Count -eq $true)
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Ping, LDAP and RPC Connectivity Passed</td>"
        }
    else
        {
            $IndexDC9 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Connectivity test failed</font></td>" 
        }

    if (($DCDiag | Select-String -Pattern 'passed test NCSecDesc').Count -eq $true)
        {
            $Pass = $DCDiag | Select-String -Pattern 'passed test NCSecDesc'
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Pass</td>"
        }
    else
        {
            $IndexDC9 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Test failed</font></td>" 
        }

    }

Add-Content $report "</tr>" 
 
Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Checks that the security descriptors on the naming context heads have appropriate permissions for replication. For more details regarding the tool, check '<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731968(v%3Dws.11)'>DCDiag</a>'.Also, verify '<a href='https://blogs.technet.microsoft.com/askds/2011/03/22/what-does-dcdiag-actually-do/'>What does DCDiag actually do</a>' for further understanding.</td></tr></TABLE>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Obs. Before the main test is made, the basic connectivity with the DC (DNS check, ICMP and RPC) is validated. This validation also includes LDAP binding (<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755809(v=ws.10)'>How Active Directory Searches Work</a>).</td></tr></TABLE>"

add-content $report  "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"



######################################### NetLogons ############################################


add-content $report "<div id='NetLogons'></div>"

add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>NetLogons Validation</h3>" 
add-content $report  "</CENTER>"
add-content $report  "<BR>"
 
add-content $report  "<table width='80%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Connectivity</B></td>" 
Add-Content $report  "<td width='20%' align='center'><B>NetLogons</B></td>" 

 
Add-Content $report "</tr>" 

$DCs = $Forest.domains | ForEach-Object {$_.DomainControllers} | ForEach-Object {$_.Name} 
$IndexDC10 = 0
foreach ($DC in $DCs)
    {
    Add-Content $report "<tr>"

    $DCDiag = start-job -scriptblock {dcdiag /test:NetLogons /s:$($args[0])} -ArgumentList $DC
    wait-job -Job $DCDiag -Timeout 20
    $DCDiag = receive-job -job $DCDiag


    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DC</td>" 



    if (($DCDiag | Select-String -Pattern 'passed test Connectivity').Count -eq $true)
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Ping, LDAP and RPC Connectivity Passed</td>"
        }
    else
        {
            $IndexDC10 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Connectivity test failed</font></td>" 
        }

    if (($DCDiag | Select-String -Pattern 'passed test NetLogons').Count -eq $true)
        {
            $Pass = $DCDiag | Select-String -Pattern 'passed test NetLogons'
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Pass</td>"
        }
    else
        {
            $IndexDC10 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Test failed</font></td>" 
        }

    }

Add-Content $report "</tr>" 
 
Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Checks that the appropriate logon privileges exist to allow replication to proceed. For more details regarding the tool, check '<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731968(v%3Dws.11)'>DCDiag</a>'.Also, verify '<a href='https://blogs.technet.microsoft.com/askds/2011/03/22/what-does-dcdiag-actually-do/'>What does DCDiag actually do</a>' for further understanding.</td></tr></TABLE>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Obs. Before the main test is made, the basic connectivity with the DC (DNS check, ICMP and RPC) is validated. This validation also includes LDAP binding (<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755809(v=ws.10)'>How Active Directory Searches Work</a>).</td></tr></TABLE>"

add-content $report  "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"


######################################### ObjectsReplicated ############################################


add-content $report "<div id='ObjectsReplicated'></div>"

add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>ObjectsReplicated Validation</h3>" 
add-content $report  "</CENTER>"
add-content $report  "<BR>"
 
add-content $report  "<table width='80%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Connectivity</B></td>" 
Add-Content $report  "<td width='20%' align='center'><B>ObjectsReplicated</B></td>" 

 
Add-Content $report "</tr>" 

$DCs = $Forest.domains | ForEach-Object {$_.DomainControllers} | ForEach-Object {$_.Name} 
$IndexDC11 = 0
foreach ($DC in $DCs)
    {
    Add-Content $report "<tr>"

    $DCDiag = start-job -scriptblock {dcdiag /test:ObjectsReplicated /s:$($args[0])} -ArgumentList $DC
    wait-job -Job $DCDiag -Timeout 20
    $DCDiag = receive-job -job $DCDiag


    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DC</td>" 



    if (($DCDiag | Select-String -Pattern 'passed test Connectivity').Count -eq $true)
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Ping, LDAP and RPC Connectivity Passed</td>"
        }
    else
        {
            $IndexDC11 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Connectivity test failed</font></td>" 
        }

    if (($DCDiag | Select-String -Pattern 'passed test ObjectsReplicated').Count -eq $true)
        {
            $Pass = $DCDiag | Select-String -Pattern 'passed test ObjectsReplicated'
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Pass</td>"
        }
    else
        {
            $IndexDC11 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Test failed</font></td>" 
        }

    }

Add-Content $report "</tr>" 
 
Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Checks that the Machine Account and Directory System Agent (DSA) objects have replicated. For more details regarding the tool, check '<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731968(v%3Dws.11)'>DCDiag</a>'.Also, verify '<a href='https://blogs.technet.microsoft.com/askds/2011/03/22/what-does-dcdiag-actually-do/'>What does DCDiag actually do</a>' for further understanding.</td></tr></TABLE>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Obs. Before the main test is made, the basic connectivity with the DC (DNS check, ICMP and RPC) is validated. This validation also includes LDAP binding (<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755809(v=ws.10)'>How Active Directory Searches Work</a>).</td></tr></TABLE>"

add-content $report  "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"

######################################### LocatorCheck ############################################


add-content $report "<div id='LocatorCheck'></div>"

add-content $report "<CENTER>"
add-content $report  "<CENTER>"
add-content $report  "<h3>LocatorCheck Validation</h3>" 
add-content $report  "</CENTER>"
add-content $report  "<BR>"
 
add-content $report  "<table width='80%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Connectivity</B></td>" 
Add-Content $report  "<td width='20%' align='center'><B>Replications</B></td>" 

Add-Content $report "</tr>" 

$DCs = $Forest.domains | ForEach-Object {$_.DomainControllers} | ForEach-Object {$_.Name} 
$IndexDC12 = 0
foreach ($DC in $DCs)
    {
    Add-Content $report "<tr>"

    $DCDiag = start-job -scriptblock {dcdiag /test:Replications /s:$($args[0])} -ArgumentList $DC
    wait-job -Job $DCDiag -Timeout 20
    $DCDiag = receive-job -job $DCDiag


    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DC</td>" 



    if (($DCDiag | Select-String -Pattern 'passed test Connectivity').Count -eq $true)
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Ping, LDAP and RPC Connectivity Passed</td>"
        }
    else
        {
            $IndexDC12 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Connectivity test failed</font></td>" 
        }

    if (($DCDiag | Select-String -Pattern 'passed test LocatorCheck').Count -eq $true)
        {
            $Pass = $DCDiag | Select-String -Pattern 'passed test LocatorCheck'
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Pass</td>"
        }
    else
        {
            $IndexDC12 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Test failed</font></td>" 
        }

    }

Add-Content $report "</tr>" 
Add-content $report  "</table>" 
add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>This test validates that DCLocator queries return the five 'capabilities' that any DC must know of to operate correctly (<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc737410(v=ws.10)'>Global Catalog</a>, <a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc780487(v=ws.10)'>Operations Masters</a>, <a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc773061(v=ws.10)'>Time Server</a> and <a href='https://docs.microsoft.com/en-us/windows/desktop/SecAuthN/key-distribution-center'>KDC</a>). For more details regarding the tool, check '<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731968(v%3Dws.11)'>DCDiag</a>'.Also, verify '<a href='https://blogs.technet.microsoft.com/askds/2011/03/22/what-does-dcdiag-actually-do/'>What does DCDiag actually do</a>' for further understanding.</td></tr></TABLE>"
add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Obs. Before the main test is made, the basic connectivity with the DC (DNS check, ICMP and RPC) is validated. This validation also includes LDAP binding (<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755809(v=ws.10)'>How Active Directory Searches Work</a>).</td></tr></TABLE>"

add-content $report  "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"

######################################### RidManager ############################################

add-content $report "<div id='RidManager'></div>"
add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>RidManager Validation</h3>" 
add-content $report  "</CENTER>"
add-content $report  "<BR>"
 
add-content $report  "<table width='80%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Connectivity</B></td>" 
Add-Content $report  "<td width='20%' align='center'><B>RidManager</B></td>" 

Add-Content $report "</tr>" 

$DCs = $Forest.domains | ForEach-Object {$_.DomainControllers} | ForEach-Object {$_.Name} 
$IndexDC13 = 0
foreach ($DC in $DCs)
    {
    Add-Content $report "<tr>"

    $DCDiag = start-job -scriptblock {dcdiag /test:RidManager /s:$($args[0])} -ArgumentList $DC
    wait-job -Job $DCDiag -Timeout 20
    $DCDiag = receive-job -job $DCDiag


    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DC</td>" 



    if (($DCDiag | Select-String -Pattern 'passed test Connectivity').Count -eq $true)
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Ping, LDAP and RPC Connectivity Passed</td>"
        }
    else
        {
            $IndexDC13 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Connectivity test failed</font></td>" 
        }

    if (($DCDiag | Select-String -Pattern 'passed test RidManager').Count -eq $true)
        {
            $Pass = $DCDiag | Select-String -Pattern 'passed test RidManager'
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Pass</td>"
        }
    else
        {
            $IndexDC13 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Test failed</font></td>" 
        }

    }

Add-Content $report "</tr>" 
 
Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Checks whether the relative identifier (RID) master is accessible and if it contains the proper information. For more details regarding the tool, check '<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731968(v%3Dws.11)'>DCDiag</a>'.Also, verify '<a href='https://blogs.technet.microsoft.com/askds/2011/03/22/what-does-dcdiag-actually-do/'>What does DCDiag actually do</a>' for further understanding.</td></tr></TABLE>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Obs. Before the main test is made, the basic connectivity with the DC (DNS check, ICMP and RPC) is validated. This validation also includes LDAP binding (<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755809(v=ws.10)'>How Active Directory Searches Work</a>).</td></tr></TABLE>"

add-content $report  "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"


######################################### Services ############################################


add-content $report "<div id='Services'></div>"

add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>Services Validation</h3>" 
add-content $report  "</CENTER>"
add-content $report  "<BR>"
 
add-content $report  "<table width='80%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Connectivity</B></td>" 
Add-Content $report  "<td width='20%' align='center'><B>Services</B></td>" 

 
Add-Content $report "</tr>" 

$DCs = $Forest.domains | ForEach-Object {$_.DomainControllers} | ForEach-Object {$_.Name} 
$IndexDC14 = 0
foreach ($DC in $DCs)
    {
    Add-Content $report "<tr>"

    $DCDiag = start-job -scriptblock {dcdiag /test:Services /s:$($args[0])} -ArgumentList $DC
    wait-job -Job $DCDiag -Timeout 20
    $DCDiag = receive-job -job $DCDiag


    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DC</td>" 



    if (($DCDiag | Select-String -Pattern 'passed test Connectivity').Count -eq $true)
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Ping, LDAP and RPC Connectivity Passed</td>"
        }
    else
        {
            $IndexDC14 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Connectivity test failed</font></td>" 
        }

    if (($DCDiag | Select-String -Pattern 'passed test Services').Count -eq $true)
        {
            $Pass = $DCDiag | Select-String -Pattern 'passed test Services'
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Pass</td>"
        }
    else
        {
            $IndexDC14 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Test failed</font></td>" 
        }

    }

Add-Content $report "</tr>" 
 
Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Checks whether the appropriate domain controller services are running. For more details regarding the tool, check '<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731968(v%3Dws.11)'>DCDiag</a>'.Also, verify '<a href='https://blogs.technet.microsoft.com/askds/2011/03/22/what-does-dcdiag-actually-do/'>What does DCDiag actually do</a>' for further understanding.</td></tr></TABLE>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Obs. Before the main test is made, the basic connectivity with the DC (DNS check, ICMP and RPC) is validated. This validation also includes LDAP binding (<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755809(v=ws.10)'>How Active Directory Searches Work</a>).</td></tr></TABLE>"

add-content $report  "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"


######################################### SystemLog ############################################


add-content $report "<div id='SystemLog'></div>"

add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>SystemLog Validation</h3>" 
add-content $report  "</CENTER>"
add-content $report  "<BR>"

add-content $report  "<table width='80%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Connectivity</B></td>" 
Add-Content $report  "<td width='20%' align='center'><B>SystemLog</B></td>" 

 
Add-Content $report "</tr>" 

$DCs = $Forest.domains | ForEach-Object {$_.DomainControllers} | ForEach-Object {$_.Name} 
$IndexDC15 = 0
foreach ($DC in $DCs)
    {
    Add-Content $report "<tr>"

    $DCDiag = start-job -scriptblock {dcdiag /test:SystemLog /s:$($args[0])} -ArgumentList $DC
    wait-job -Job $DCDiag -Timeout 20
    $DCDiag = receive-job -job $DCDiag


    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DC</td>" 



    if (($DCDiag | Select-String -Pattern 'passed test Connectivity').Count -eq $true)
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Ping, LDAP and RPC Connectivity Passed</td>"
        }
    else
        {
            $IndexDC15 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Connectivity test failed</font></td>" 
        }

    if (($DCDiag | Select-String -Pattern 'passed test SystemLog').Count -eq $true)
        {
            $Pass = $DCDiag | Select-String -Pattern 'passed test SystemLog'
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Pass</td>"
        }
    else
        {
            $IndexDC15 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Test failed</font></td>" 
        }

    }

Add-Content $report "</tr>" 
 
Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<BR><TABLE BORDER=0 WIDTH=95%><tr><td>Checks that the system is running without errors. For more details regarding the tool, check '<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731968(v%3Dws.11)'>DCDiag</a>'.Also, verify '<a href='https://blogs.technet.microsoft.com/askds/2011/03/22/what-does-dcdiag-actually-do/'>What does DCDiag actually do</a>' for further understanding.</td></tr></TABLE>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Obs. Before the main test is made, the basic connectivity with the DC (DNS check, ICMP and RPC) is validated. This validation also includes LDAP binding (<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755809(v=ws.10)'>How Active Directory Searches Work</a>).</td></tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"


######################################### VerifyReferences ############################################


add-content $report "<div id='VerifyReferences'></div>"

add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>VerifyReferences Validation</h3>" 
add-content $report  "</CENTER>"
add-content $report  "<BR>"

add-content $report  "<table width='80%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Connectivity</B></td>" 
Add-Content $report  "<td width='20%' align='center'><B>VerifyReferences</B></td>" 

 
Add-Content $report "</tr>" 

$DCs = $Forest.domains | ForEach-Object {$_.DomainControllers} | ForEach-Object {$_.Name} 
$IndexDC16 = 0
foreach ($DC in $DCs)
    {
    Add-Content $report "<tr>"

    $DCDiag = start-job -scriptblock {dcdiag /test:VerifyReferences /s:$($args[0])} -ArgumentList $DC
    wait-job -Job $DCDiag -Timeout 20
    $DCDiag = receive-job -job $DCDiag


    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DC</td>" 



    if (($DCDiag | Select-String -Pattern 'passed test Connectivity').Count -eq $true)
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Ping, LDAP and RPC Connectivity Passed</td>"
        }
    else
        {
            $IndexDC16 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Connectivity test failed</font></td>" 
        }

    if (($DCDiag | Select-String -Pattern 'passed test VerifyReferences').Count -eq $true)
        {
            $Pass = $DCDiag | Select-String -Pattern 'passed test VerifyReferences'
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Pass</td>"
        }
    else
        {
            $IndexDC16 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Test failed</font></td>" 
        }

    }

Add-Content $report "</tr>" 
 
Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Checks that certain system references are intact for the FRS and replication infrastructure. For more details regarding the tool, check '<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731968(v%3Dws.11)'>DCDiag</a>'.Also, verify '<a href='https://blogs.technet.microsoft.com/askds/2011/03/22/what-does-dcdiag-actually-do/'>What does DCDiag actually do</a>' for further understanding.</td></tr></TABLE>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Obs. Before the main test is made, the basic connectivity with the DC (DNS check, ICMP and RPC) is validated. This validation also includes LDAP binding (<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755809(v=ws.10)'>How Active Directory Searches Work</a>).</td></tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"



######################################### CrossRefValidation ############################################


add-content $report "<div id='CrossRefValidation'></div>"

add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>CrossRefValidation Validation</h3>" 
add-content $report "<BR>"
add-content $report  "</CENTER>"
 
add-content $report  "<table width='80%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Connectivity</B></td>" 
Add-Content $report  "<td width='20%' align='center'><B>CrossRefValidation</B></td>" 

 
Add-Content $report "</tr>" 

$DCs = $Forest.domains | ForEach-Object {$_.DomainControllers} | ForEach-Object {$_.Name} 
$IndexDC17 = 0
foreach ($DC in $DCs)
    {
    Add-Content $report "<tr>"

    $DCDiag = start-job -scriptblock {dcdiag /test:CrossRefValidation /s:$($args[0])} -ArgumentList $DC
    wait-job -Job $DCDiag -Timeout 20
    $DCDiag = receive-job -job $DCDiag


    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DC</td>" 



    if (($DCDiag | Select-String -Pattern 'passed test Connectivity').Count -eq $true)
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Ping, LDAP and RPC Connectivity Passed</td>"
        }
    else
        {
            $IndexDC17 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Connectivity test failed</font></td>" 
        }

    if (($DCDiag | Select-String -Pattern 'passed test CrossRefValidation').Count -eq $true)
        {
            $Pass = $DCDiag | Select-String -Pattern 'passed test CrossRefValidation'
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Pass</td>"
        }
    else
        {
            $IndexDC17 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Test failed</font></td>" 
        }

    }

Add-Content $report "</tr>" 
 
Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Checks the validity of cross-references. For more details regarding the tool, check '<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731968(v%3Dws.11)'>DCDiag</a>'.Also, verify '<a href='https://blogs.technet.microsoft.com/askds/2011/03/22/what-does-dcdiag-actually-do/'>What does DCDiag actually do</a>' for further understanding.</td></tr></TABLE>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Obs. Before the main test is made, the basic connectivity with the DC (DNS check, ICMP and RPC) is validated. This validation also includes LDAP binding (<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755809(v=ws.10)'>How Active Directory Searches Work</a>).</td></tr></TABLE><BR>" 

add-content $report  "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"



######################################### CheckSDRefDom ############################################


add-content $report "<div id='CheckSDRefDom'></div>"

add-content $report "<CENTER>"

add-content $report  "<CENTER>"
add-content $report  "<h3>CheckSDRefDom Validation</h3>" 
add-content $report  "</CENTER>"
add-content $report "<BR>"

add-content $report  "<table width='80%' border='1'>" 
Add-Content $report  "<tr bgcolor='WhiteSmoke'>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Domain Controller</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Connectivity</B></td>" 
Add-Content $report  "<td width='20%' align='center'><B>CheckSDRefDom</B></td>" 

 
Add-Content $report "</tr>" 

$DCs = $Forest.domains | ForEach-Object {$_.DomainControllers} | ForEach-Object {$_.Name} 
$IndexDC18 = 0
foreach ($DC in $DCs)
    {
    Add-Content $report "<tr>"

    $DCDiag = start-job -scriptblock {dcdiag /test:CheckSDRefDom /s:$($args[0])} -ArgumentList $DC
    wait-job -Job $DCDiag -Timeout 20
    $DCDiag = receive-job -job $DCDiag


    Add-Content $report "<td bgcolor='White' align=center>$Domain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$DC</td>" 



    if (($DCDiag | Select-String -Pattern 'passed test Connectivity').Count -eq $true)
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>Ping, LDAP and RPC Connectivity Passed</td>"
        }
    else
        {
            $IndexDC18 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Connectivity test failed</font></td>" 
        }

    if (($DCDiag | Select-String -Pattern 'passed test CheckSDRefDom').Count -eq $true)
        {
            $Pass = $DCDiag | Select-String -Pattern 'passed test CheckSDRefDom'
            Add-Content $report "<td bgcolor= 'Lime' align=center>$Pass</td>"
        }
    else
        {
            $IndexDC18 ++
            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>Test failed</font></td>" 
        }

    }

Add-Content $report "</tr>" 
 
Add-content $report  "</table>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Checks that all application directory partitions have appropriate security descriptor reference domains. For more details regarding the tool, check '<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731968(v%3Dws.11)'>DCDiag</a>'.Also, verify '<a href='https://blogs.technet.microsoft.com/askds/2011/03/22/what-does-dcdiag-actually-do/'>What does DCDiag actually do</a>' for further understanding.</td></tr></TABLE>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Obs. Before the main test is made, the basic connectivity with the DC (DNS check, ICMP and RPC) is validated. This validation also includes LDAP binding (<a href='https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755809(v=ws.10)'>How Active Directory Searches Work</a>).</td></tr></TABLE><BR>" 

add-content $report  "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"


######################################### DNS HEADER #############################################



add-content $report  "<table width='100%' border='0'>" 
add-content $report  "<tr bgcolor='White'>" 
add-content $report  "<td colspan='7' height='70' align='center'>" 
add-content $report  "<font face='verdana' color='#000000' size='62'>DNS Servers<HR></font>" 
add-content $report  "</td>" 
add-content $report  "</tr>" 
add-content $report  "</table>" 

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"



######################################### DNS Server #############################################


add-content $report "<div id='DNSServers'></div>"

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
Add-Content $report  "<td width='10%' align='center'><B>Suspicious Root Hints</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Tombstone Interval</B></td>" 
Add-Content $report  "<td width='10%' align='center'><B>Server Recursion Enabled</B></td>"
Add-Content $report  "<td width='10%' align='center'><B>Bind Secondaries Enabled</B></td>" 

 
Add-Content $report "</tr>" 


$IndexDNS0 = 0
Foreach ($Domain0 in $Forest.Domains.Name)
    {
        $DCs = $Forest.domains | ForEach-Object {$_.DomainControllers} | ForEach-Object {$_.Name} 

        foreach ($DC in $DCs)
            {
                try{
                $DNS = Get-DnsServer -ComputerName $DC

                if ($DNS -ne '')
                    {

                $DNSRootHintC = @()
                Foreach ($dd in $dns.ServerRootHint.NameServer.RecordData)
                    {
                        if ($dd.NameServer -notlike '*.root-servers.net.')
                            {
                                $DNSRootHintC += $dd.NameServer
                            }
                    }
                

                $DNSName = $DNS.ServerSetting.ComputerName
                $DNSTomb = $DNS.ServerDsSetting.TombstoneInterval
                $DNSBindSec = $DNS.ServerSetting.BindSecondaries
                $DNSSca = $DNS.ServerScavenging.ScavengingState
                $DNSRecur = $DNS.ServerRecursion.Enable
                $DNSZoneCount = ($DNS.ServerZone | where {$_.ZoneName -notlike '*.arpa' -and $_.ZoneName -ne 'TrustAnchors'}).Count
                $DNSRootC = $DNSRootHintC.Count


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

                if ($DNSRootC -eq '' -or $DNSRootC -eq 0)
                    {
                        Add-Content $report "<td bgcolor= 'Lime' align=center>0</td>"
                    }
                else  
                    { 
                        $IndexDNS0 ++
                        Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$DNSRootC</font></td>" 
                    }

                Add-Content $report "<td bgcolor='White' align=center>$DNSTomb</td>" 
                if ($DNSRecur -eq $false)
                    {
                        Add-Content $report "<td bgcolor= 'Lime' align=center>$DNSRecur</td>"
                    }
                else  
                    { 
                        $IndexDNS0 ++
                        Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$DNSRecur</font></td>" 
                    }
                Add-Content $report "<td bgcolor='White' align=center>$DNSBindSec</td>" 


                }
                }
                catch {}
            }
    }

Add-Content $report "</tr>" 
 
Add-content $report  "</table>"

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<CENTER>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td> DNS Server is an important part of Active Directory so it's maintenance is very critical for the safety and funtionality of the environment, if you did not disabled recursion don't forget to do so according to <a href='https://support.microsoft.com/hr-ba/help/2678371/microsoft-dns-server-vulnerability-to-dns-server-cache-snooping-attack'>'Microsoft DNS Server vulnerability to DNS Server Cache snooping attacks'</a>. Enabling <B>Scavaging</B> is also very important to avoid old records in the DNS. Also verify the <B>forwarders</B> and <B>conditional forwarders</B>.</td></tr></TABLE>" 

add-content $report  "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"



######################################### AD OBJECTS HEADER #############################################


add-content $report "<div id='Objects'></div>"

add-content $report  "<table width='100%' border='0'>" 
add-content $report  "<tr bgcolor='White'>" 
add-content $report  "<td colspan='7' height='70' align='center'>" 
add-content $report  "<font face='tahoma' color='#000000' size='62'>Users and Computers<HR></font>" 
add-content $report  "</td>" 
add-content $report  "</tr>" 
add-content $report  "</table>" 

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>This section should give a overall perspective of the user accounts in the environment. As so as the overall maintenance and health of the user accounts in the environment. Verify the informations reported from time to time to keep your environment healthy and to prevent futher problems and security risks regarding user accounts.</td></tr></TABLE>" 


add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"


######################################### USERS #############################################


add-content $report "<div id='Users'></div>"

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

$IndexUser0 = 0

Foreach ($Contr in $Forest.domains.PdcRoleOwner) 
    {
        Add-Content $report "<tr>" 
        $UsDomain = $Contr.Domain
        $AllUsers = (dsquery * -filter sAMAccountType=805306368 -s $Contr -attr samAccountName -attrsonly -limit 0).Count

        $UsersDisabled = (dsquery user -disabled -s $Contr -limit 0).Count
        $UsersEnabled = ($AllUsers - $UsersDisabled)
        $UsersInactive = (dsquery user -inactive 12 -s $Contr -limit 0).Count
        $UsersPWDNeverExpire = (dsquery user -stalepwd 0 -s $Contr -limit 0).Count

        Add-Content $report "<td bgcolor='White' align=center>$UsDomain</td>" 
        Add-Content $report "<td bgcolor='White' align=center>$AllUsers</td>"         
        Add-Content $report "<td bgcolor='White' align=center>$UsersEnabled</td>"               
        Add-Content $report "<td bgcolor='White' align=center>$UsersDisabled</td>"    
        if ($UsersInactive -eq '' -or $UsersInactive -eq 0) 
            {
                Add-Content $report "<td bgcolor= 'Lime' align=center>0</td>"
            }
        else 
            { 
                $IndexUser0 ++
                Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$UsersInactive</font></td>" 
            }
        if ($UsersPWDNeverExpire -eq '' -or $UsersPWDNeverExpire -eq 0) 
            {
                Add-Content $report "<td bgcolor= 'Lime' align=center>0</td>"
            }
        else 
            { 
                $IndexUser0 ++
                Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$UsersPWDNeverExpire</font></td>" 
            }
    }

Add-Content $report "</tr>"
 
Add-content $report  "</table>" 

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report "<TABLE BORDER=0 WIDTH=95%><tr><td>This overview state of user accounts will present the <B>Total number of users</b>, the <B>Disabled User Accounts</B>, <B>Inactive Users </B> and User Accounts that never changed they passwords (that are probabily <B>'Password Never Expires'</B> accounts). Most of those counters should be <B>0</B> or the smallest as possible. Exceptions may apply, but should not be a common practice.</td></tr></TABLE>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"


######################################### COMPUTER ACCOUNTS #############################################


add-content $report "<div id='Computers'></div>"


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

$IndexPC0 = 0

Foreach ($Contr in $Forest.domains.PdcRoleOwner) 
    {

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

    Add-Content $report "<td bgcolor='White' align=center>$PCDomain</td>" 
    Add-Content $report "<td bgcolor='White' align=center>$PCAllC</td>"         
    Add-Content $report "<td bgcolor='White' align=center>$PCWS</td>"
    Add-Content $report "<td bgcolor='White' align=center>$PCServer</td>"               
    if ($PCWSUnsupp -eq '' -or $PCWSUnsupp -eq 0) 
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>0</td>"
        }
     else 
        { 
           $IndexPC0 ++
           Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$PCWSUnsupp</font></td>" 
        }
    if ($PCServerUnsupp -eq '' -or $PCServerUnsupp -eq 0)  
        {
            Add-Content $report "<td bgcolor= 'Lime' align=center>0</td>"
        }
    else 
        { 
          $IndexPC0 ++
          Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$PCServerUnsupp</font></td>" 
        }
    }

Add-Content $report "</tr>"
 
Add-content $report  "</table>" 

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report "<TABLE BORDER=0 WIDTH=95%><tr><td>Those counters present a list of total Windows Servers and Workstations, total number of Windows Servers and Workstations that are enabled and have unsupported Operating Systems.</td></tr></TABLE>"  

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"



######################################### GROUPS HEADER #############################################

add-content $report "<div id='GroupHeader'></div>"

add-content $report  "<table width='100%' border='0'>" 
add-content $report  "<tr bgcolor='White'>" 
add-content $report  "<td colspan='7' height='70' align='center'>" 
add-content $report  "<font face='tahoma' color='#000000' size='62'>Groups<HR></font>" 
add-content $report  "</td>" 
add-content $report  "</tr>" 
add-content $report  "</table>" 

add-content $report "<TABLE BORDER=0 WIDTH=95%><tr><td>This section will verify the number of members in critical administration groups in the Forest and Domain and will alert for every group with more than 30 members (including Users, Computers and other Groups).</td></tr></TABLE>"  

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"


######################################### GROUPS #############################################


add-content $report "<div id='GroupOverview'></div>"

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

$IndexGroup0 = 0

Foreach ($Contr in $Forest.domains.PdcRoleOwner) 
    {
        Foreach ($gp in $Groups)
            {
            $temp = ('(&(objectclass=group)(sAMAccountName='+$gp+'))')
            $GpTemp = 0
            $GpTemp = (dsquery * -filter $temp -s $Contr -Attr member -limit 0)
            if (($GpTemp).Count -ge 2)
                {
                    $GCounter = (($GpTemp -split(';')).Count - 1)
                    $GDomain = $Contr.Domain
                    $GName = $gp
                    Add-Content $report "<tr>"
                    Add-Content $report "<td bgcolor='White' align=center>$GDomain</td>" 
                    Add-Content $report "<td bgcolor='White' align=center>$GName</td>" 
                    if ($GCounter -ge 5) 
                        {
                            $IndexGroup0 ++
                            Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GCounter</font></td>"
                        }
                    else 
                        { 
                            Add-Content $report "<td bgcolor='White' align=center>$GCounter</td>" 
                        } 
                }
            } 
    }
Add-Content $report "</tr>"
 
Add-content $report  "</table>" 

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Having far too many users with more than necessary permissions may result in serius security breaches. Make sure only the very necessary user accounts are present in those groups, unautohorized users may cause big damage. And remember to review the <a href='https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory'>Best Practices for Securing Active Directory</a>. And specialy '<a href='https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models'>Implementing Least-Privilege Administrative Models</a>'.</td></tr></TABLE>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"


######################################### EMPTY GROUPS #############################################

add-content $report "<div id='Groups'></div>"


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

$IndexGroup1 = 0
Foreach ($Contr in $Forest.domains.PdcRoleOwner) 
    {
        $GroupsMembers = @()
        Add-Content $report "<tr>" 
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
        Add-Content $report "<td bgcolor='White' align=center>$PCDomain</td>" 
        Add-Content $report "<td bgcolor='White' align=center>$GroupTotal</td>" 
        if ($GroupLarge -ge 5 -and  $GroupLarge -lt 20) 
            {
                Add-Content $report "<td bgcolor= 'Yellow' align=center> $GroupLarge</td>"
            }
        if ($GroupLarge -gt 30) 
            {
                $IndexGroup1 ++
                Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GroupLarge</font></td>"
            }
        else 
            { 
                Add-Content $report "<td bgcolor= 'Lime' align=center> $GroupLarge</td>" 
            }

        if ($GroupEmpty -ge 5 -and $GroupEmpty -lt 20) 
            {
                Add-Content $report "<td bgcolor= 'Yellow' align=center>$GroupEmpty</td>"
            }
        if ($GroupEmpty -gt 20) 
            {
                $IndexGroup1 ++
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
                $IndexGroup1 ++
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
 
Add-content $report  "</table>" 

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Having fair number of groups is not also a good practice, it's vital to ensure an easier and 'clean' management of Active Directory, usually don't make sense have more groups than users or groups too small. And remember to review the <a href='https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory'>Best Practices for Securing Active Directory</a>. And specialy '<a href='https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models'>Implementing Least-Privilege Administrative Models</a>'.</td></tr></TABLE>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"



######################################### GPO HEADER #############################################


add-content $report "<div id='GPOHeader'></div>"

add-content $report  "<table width='100%' border='0'>" 
add-content $report  "<tr bgcolor='White'>" 
add-content $report  "<td colspan='7' height='70' align='center'>" 
add-content $report  "<font face='tahoma' color='#000000' size='62'>Group Policy Objects<HR></font>" 
add-content $report  "</td>" 
add-content $report  "</tr>" 
add-content $report  "</table>" 

add-content $report "<TABLE BORDER=0 WIDTH=95%><tr><td>This section will verify the avarage status of Group Policies in the Forest and Domain and will alert for every group policy with <B>too many configurations</B>, <B>withou any configuration</b> at all, or <B>not linked to any OU</B>.</td></tr></TABLE>"  

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"

######################################### GPOs #############################################

add-content $report "<div id='GPOOverview'></div>"

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

$IndexGPO0 = 0

Foreach ($Contr in $Forest.domains.PdcRoleOwner) 
    {
        Try
            {
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
                if ($GpoC2 -ge 1) 
                    {
                        $IndexGPO0 ++
                        Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GpoC2 GPOs</font></td>"
                    }
                else 
                    { 
                        Add-Content $report "<td bgcolor= 'Lime' align=center>$GpoC2 GPOs</td>" 
                    }
                if ($GPEmpt -ge 1) 
                    {
                        $IndexGPO0 ++
                        Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GPEmpt GPOs</font></td>"
                    }
                else 
                    { 
                        Add-Content $report "<td bgcolor= 'Lime' align=center>$GPEmpt GPOs</td>" 
                    }
                if ($GPBIG -ge 1) 
                    {
                        $IndexGPO0 ++
                        Add-Content $report "<td bgcolor= 'Red' align=center><font color='#FFFFFF'>$GPBIG GPOs</font></td>"
                    }
                else 
                    { 
                        Add-Content $report "<td bgcolor= 'Lime' align=center>$GPBIG GPOs</td>" 
                    }
            }
        Catch {}
    }

Add-Content $report "</tr>"
 
Add-content $report  "</table>" 

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Group Policy represent an important part of Active Directory management (without mention its impact on Servers and Workstation). Make sure GPO conflicts are avoided always as possible, also take GPO backups at a regular basis (<a href='https://docs.microsoft.com/en-us/powershell/module/grouppolicy/backup-gpo?view=win10-ps'>Backup-GPO</a>).</td></tr></TABLE>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"


######################################### GPOs WITHOUT LINK #############################################


add-content $report "<div id='GPOs'></div>"

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

$IndexGPO1 = 0

Foreach ($Contr in $Forest.domains.PdcRoleOwner) 
    {
        Try
            {
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
                        
                        $IndexGPO1 ++
                        $GpoName = $Gpo.DisplayName
                        $GpoUserADVer = $Gpo.User.DSVersion
                        $GpoCompADVer = $Gpo.Computer.DSVersion
                        $GpoModDate =  $Gpo.ModificationTime

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
            Catch {}
    }
 
Add-content $report  "</table>" 

add-content $report "<BR>"
add-content $report "<BR>"

add-content $report  "<TABLE BORDER=0 WIDTH=95%><tr><td>Make sure to investigate and solve problems listed here, Having too many unsued GPOs may impact your Active Directory management effort.</td></tr></TABLE>" 

add-content $report "</CENTER>"

add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"
add-content $report "<BR>"


######################################### INDEX #############################################



}
$Measure = $Runtime.TotalSeconds.ToString('#######.##')

$index = Get-Content "C:\ADHC\ADHC_Report.htm"

$Index[23] = "<TABLE BORDER=0 WIDTH=20% align='right'><tr><td align='right'><font face='verdana' color='#000000' size='4'> Execution: $Measure seconds<HR></font></td></tr></TABLE>"

$i = 38

$index[$i] = "<ol>"
$i++
$index[$i] = "<ul><a href='#ForestHeader'>Forest</a>"
$i++
$index[$i] = "<ul>"
$i++
if ($IndexForest0 -eq 0) 
    {
        $index[$i] = "<li><a href='#ForestOverview'> Overview ($IndexForest0 Errors)</a></li>"
    }
else 
    { 
        $index[$i] = "<li><a href='#ForestOverview'> Overview (<font color='#FF0000'>$IndexForest0</font> Errors)</a></li>"
    }
$i++
$index[$i] = "<li><a href='#TrustOverview'> Active Directory Trusts</a></li>"
$i++
if ($IndexDomain0 -eq 0) 
    {
        $index[$i] = "<li><a href='#DomainOverview'> Domains ($IndexDomain0 Errors)</a></li>"
    }
else 
    { 
        $index[$i] = "<li><a href='#DomainOverview'> Domains (<font color='#FF0000'>$IndexDomain0</font> Errors)</a></li>"
    }
$i++
if ($IndexDC0 -eq 0) 
    {
        $index[$i] = "<li><a href='#DCOverview'> Domain Controllers ($IndexDC0 Errors)</a></li>"
    }
else 
    { 
        $index[$i] = "<li><a href='#DCOverview'> Domain Controllers (<font color='#FF0000'>$IndexDC0</font> Errors)</a></li>"
    }
$i++
$index[$i] = "</ul>"
$i++
$index[$i] = "</ul>"
$i++
$index[$i] = "<ul><a href='#DCHealth'> Domain Controller's Health</a>"
$i++
$index[$i] = "<ul>"
$i++
if ($IndexDC2 -eq 0) 
    {
        $index[$i] = "<li><a href='#Advertising'> Advertising Validation ($IndexDC2 Errors)</a></li>"
    }
else 
    { 
        $index[$i] = "<li><a href='#Advertising'> Advertising Validation (<font color='#FF0000'>$IndexDC2</font> Errors)</a></li>"
    }
$i++
if ($IndexDC3 -eq 0) 
    {
        $index[$i] = "<li><a href='#FrsEvent'> FrsEvent Validation ($IndexDC3 Errors)</a></li>"
    }
else 
    { 
        $index[$i] = "<li><a href='#FrsEvent'> FrsEvent Validation (<font color='#FF0000'>$IndexDC3</font> Errors)</a></li>"
    }
$i++
if ($IndexDC4 -eq 0) 
    {
        $index[$i] = "<li><a href='#DFSREvent'> DFSREvent Validation ($IndexDC4 Errors)</a></li>"
    }
else 
    { 
        $index[$i] = "<li><a href='#DFSREvent'> DFSREvent Validation (<font color='#FF0000'>$IndexDC4</font> Errors)</a></li>"
    }
$i++
if ($IndexDC5 -eq 0) 
    {
        $index[$i] = "<li><a href='#SysVolCheck'> SysVolCheck Validation ($IndexDC5 Errors)</a></li>"
    }
else 
    { 
        $index[$i] = "<li><a href='#SysVolCheck'> SysVolCheck Validation (<font color='#FF0000'>$IndexDC5</font> Errors)</a></li>"
    }
$i++
if ($IndexDC6 -eq 0) 
    {
        $index[$i] = "<li><a href='#KccEvent'> KccEvent Validation ($IndexDC6 Errors)</a></li>"
    }
else 
    { 
        $index[$i] = "<li><a href='#KccEvent'> KccEvent Validation (<font color='#FF0000'>$IndexDC6</font> Errors)</a></li>"
    }
$i++
if ($IndexDC7 -eq 0) 
    {
        $index[$i] = "<li><a href='#KnowsOfRoleHolders'> KnowsOfRoleHolders Validation ($IndexDC7 Errors)</a></li>"
    }
else 
    { 
        $index[$i] = "<li><a href='#KnowsOfRoleHolders'> KnowsOfRoleHolders Validation (<font color='#FF0000'>$IndexDC7</font> Errors)</a></li>"
    }
$i++
if ($IndexDC8 -eq 0) 
    {
        $index[$i] = "<li><a href='#MachineAccount'> MachineAccount Validation ($IndexDC8 Errors)</a></li>"
    }
else 
    { 
        $index[$i] = "<li><a href='#MachineAccount'> MachineAccount Validation (<font color='#FF0000'>$IndexDC8</font> Errors)</a></li>"
    }
$i++
if ($IndexDC9 -eq 0) 
    {
        $index[$i] = "<li><a href='#NCSecDesc'> NCSecDesc Validation ($IndexDC9 Errors)</a></li>"
    }
else 
    { 
        $index[$i] = "<li><a href='#NCSecDesc'> NCSecDesc Validation (<font color='#FF0000'>$IndexDC9</font> Errors)</a></li>"
    }
$i++
if ($IndexDC10 -eq 0) 
    {
        $index[$i] = "<li><a href='#NetLogons'> NetLogons Validation ($IndexDC10 Errors)</a></li>"
    }
else 
    { 
        $index[$i] = "<li><a href='#NetLogons'> NetLogons Validation (<font color='#FF0000'>$IndexDC10</font> Errors)</a></li>"
    }
$i++
if ($IndexDC11 -eq 0) 
    {
        $index[$i] = "<li><a href='#ObjectsReplicated'> ObjectsReplicated Validation ($IndexDC11 Errors)</a></li>"
    }
else 
    { 
        $index[$i] = "<li><a href='#ObjectsReplicated'> ObjectsReplicated Validation (<font color='#FF0000'>$IndexDC11</font> Errors)</a></li>"
    }
$i++
if ($IndexDC12 -eq 0) 
    {
        $index[$i] = "<li><a href='#LocatorCheck'> LocatorCheck Validation ($IndexDC12 Errors)</a></li>"
    }
else 
    { 
        $index[$i] = "<li><a href='#LocatorCheck'> LocatorCheck Validation (<font color='#FF0000'>$IndexDC12</font> Errors)</a></li>"
    }
$i++
if ($IndexDC13 -eq 0) 
    {
        $index[$i] = "<li><a href='#RidManager'> RidManager Validation ($IndexDC13 Errors)</a></li>"
    }
else 
    { 
        $index[$i] = "<li><a href='#RidManager'> RidManager Validation (<font color='#FF0000'>$IndexDC13</font> Errors)</a></li>"
    }
$i++
if ($IndexDC14 -eq 0) 
    {
        $index[$i] = "<li><a href='#Services'> Services Validation ($IndexDC14 Errors)</a></li>"
    }
else 
    { 
        $index[$i] = "<li><a href='#Services'> Services Validation (<font color='#FF0000'>$IndexDC14</font> Errors)</a></li>"
    }
$i++
if ($IndexDC15 -eq 0) 
    {
        $index[$i] = "<li><a href='#SystemLog'> SystemLog Validation ($IndexDC15 Errors)</a></li>"
    }
else 
    { 
        $index[$i] = "<li><a href='#SystemLog'> SystemLog Validation (<font color='#FF0000'>$IndexDC15</font> Errors)</a></li>"
    }
$i++
if ($IndexDC16 -eq 0) 
    {
        $index[$i] = "<li><a href='#VerifyReferences'> VerifyReferences Validation ($IndexDC16 Errors)</a></li>"
    }
else 
    { 
        $index[$i] = "<li><a href='#VerifyReferences'> VerifyReferences Validation (<font color='#FF0000'>$IndexDC16</font> Errors)</a></li>"
    }
$i++
if ($IndexDC17 -eq 0) 
    {
        $index[$i] = "<li><a href='#CrossRefValidation'> CrossRefValidation Validation ($IndexDC17 Errors)</a></li>"
    }
else 
    { 
        $index[$i] = "<li><a href='#CrossRefValidation'> CrossRefValidation Validation (<font color='#FF0000'>$IndexDC17</font> Errors)</a></li>"
    }
$i++
if ($IndexDC18 -eq 0) 
    {
        $index[$i] = "<li><a href='#CheckSDRefDom'> CheckSDRefDom Validation ($IndexDC18 Errors)</a></li>"
    }
else 
    { 
        $index[$i] = "<li><a href='#CheckSDRefDom'> CheckSDRefDom Validation (<font color='#FF0000'>$IndexDC18</font> Errors)</a></li>"
    }
$i++
$index[$i] = "</ul>"
$i++
$index[$i] = "</ul>"
$i++
$index[$i] = "<ul><a href='#DNSServers'>DNS Servers</a>"
$i++
$index[$i] = "<ul>"
$i++
if ($IndexDNS0 -eq 0) 
    {
        $index[$i] = "<li><a href='#DNSServers'> DNS Servers Health ($IndexDNS0 Errors)</a></li>"
    }
else 
    { 
        $index[$i] = "<li><a href='#DNSServers'> DNS Server Health (<font color='#FF0000'>$IndexDNS0</font> Errors)</a></li>"
    }
$i++
$index[$i] = "</ul>"
$i++
$index[$i] = "</ul>"
$i++
$index[$i] = "<ul><a href='#Objects'>Users and Computers</a>"
$i++
$index[$i] = "<ul>"
$i++
if ($IndexUser0 -eq 0) 
    {
        $index[$i] = "<li><a href='#Users'> User Accounts ($IndexUser0 Errors)</a></li>"
    }
else 
    { 
        $index[$i] = "<li><a href='#Users'> User Accounts (<font color='#FF0000'>$IndexUser0</font> Errors)</a></li>"
    }
$i++
if ($IndexPC0 -eq 0) 
    {
        $index[$i] = "<li><a href='#Computers'> Computer Accounts ($IndexPC0 Errors)</a></li>"
    }
else 
    { 
        $index[$i] = "<li><a href='#Computers'> Computer Accounts (<font color='#FF0000'>$IndexPC0</font> Errors)</a></li>"
    }
$i++
$index[$i] = "</ul>"
$i++
$index[$i] = "</ul>"
$i++
$index[$i] = "<ul><a href='#GroupHeader'>Groups</a>"
$i++
$index[$i] = "<ul>"
$i++
if ($IndexGroup0 -eq 0) 
    {
        $index[$i] = "<li><a href='#GroupOverview'> Active Directory Admin Groups ($IndexGroup0 Errors)</a></li>"
    }
else 
    { 
        $index[$i] = "<li><a href='#GroupOverview'> Active Directory Admin Groups (<font color='#FF0000'>$IndexGroup0</font> Errors)</a></li>"
    }
$i++
if ($IndexGroup1 -eq 0) 
    {
        $index[$i] = "<li><a href='#Groups'> Active Directory Groups ($IndexGroup1 Errors)</a></li>"
    }
else 
    { 
        $index[$i] = "<li><a href='#Groups'> Active Directory Groups (<font color='#FF0000'>$IndexGroup1</font> Errors)</a></li>"
    }
$i++
$index[$i] = "</ul>"
$i++
$index[$i] = "</ul>"
$i++
$index[$i] = "<ul><a href='#GPOHeader'>Group Policies</a>"
$i++
$index[$i] = "<ul>"
$i++
if ($IndexGPO0 -eq 0) 
    {
        $index[$i] = "<li><a href='#GPOOverview'> Group Policies Overview ($IndexGPO0 Errors)</a></li>"
    }
else 
    { 
        $index[$i] = "<li><a href='#GPOOverview'> Group Policies Overview (<font color='#FF0000'>$IndexGPO0</font> Errors)</a></li>"
    }
$i++
if ($IndexGPO1 -eq 0) 
    {
        $index[$i] = "<li><a href='#GPOOverview'> Empty GPOs ($IndexGPO1 Errors)</a></li>"
    }
else 
    { 
        $index[$i] = "<li><a href='#GPOOverview'> Empty GPOs (<font color='#FF0000'>$IndexGPO1</font> Errors)</a></li>"
    }
$i++
$index[$i] = "</ul>"
$i++
$index[$i] = "</ul>"
$i++
$index[$i] = "</ol>"

$index | out-file "C:\ADHC\ADHC_Report.htm"

######################################### CLOSING #############################################

Add-Content $report "</tr>"
Add-content $report  "</table>" 
add-content $report "<BR><A HREF='#top'>Back to the top</A><BR>"
add-content $report "<BR><TABLE BORDER='1' CELLPADDING='5'><TR><TD BGCOLOR='Silver'><A NAME='Disclaimer'><B>Disclaimer:</B></A> This report was generated using the ADHC Powershell Script. The information provided in this report is provided 'as-is' and is intended for information purposes only. The information present at the script is licensed 'as-is'. You bear the risk of using it. The contributors give no express warranties, guarantees or conditions. You may have additional consumer rights under your local laws which this license cannot change. To the extent permitted under your local laws, the contributors exclude the implied warranties of merchantability, fitness for a particular purpose and non-infringement. Any feedback or improvements feel free to email me at: <a href='mailto:merola@outlook.com?Subject=ADHC%20feedback' target='_top'>Claudio Merola</a></TD></TR></TABLE>"
Add-Content $report "</body>" 
Add-Content $report "</html>" 


Invoke-Item $report
