<<<<<<< HEAD
## Active Directory xRay Script

I started this as a personal project to help me during my day to day work on different Active Directory environments.

The script does not record, create or modify anything in the environment (except for creating a folder named “ADxRay” in C:\ of the computer running the script. Inside that folder the log files and the main report file named “ADxRay_Report(YEAR-MONTH-DAY).htm” is created). 

The script must be run at a Domain Controller running at least Windows Server 2012 (see requirements below). 

The script must be run by a user with Domain Admin privileges (Enterprise Admins if dealing with multiple domains and forests).

#### This script may take several hours to complete!

<BR/>

### How to run:

Just copy or download the ADxRay.ps1 and run on any computer that meets the requirements below.

<BR/>

### Requirements:

The script must be run with the following requirements:

 - Must be run on Domain Controller (due to the tools used during the inventory)
 - Must be run with rights to read objects in the entire forest and run AD Tools (dcdiag, SETSPN, dsquery, GET-AD*)
 - Must be run with elavated Powershell (Run as Administrator) - This is necessary to create the folders to keep the files generated
 - Internet connection is not required*
 
Internet connection might be use by the script for version validation, but is not a requirement. 

<BR/>

### What the script does:

This script will create the folder C:\ADxRay and run a deep inventory of your entire Active Directory environment, indicating what’s bad and what’s good. All the tests and validations are explained and contains external links to official Microsoft documentation and/or well know blog post from MVPs.

<BR/>

The Inventory phase of the script may take a long time to run depending on the size of the environment.

<BR/>

Even the script may overload the server used to run, it is not harmful to the environment. The users will not be affected and no modifications will be made in the environment (there is not a single “set-” powershell command and the only “new-“ were regarding the creation of the html report file and the xml inventory files)

<BR/>

#### Screenshots:

<BR/>

![alt text](https://github.com/ClaudioMerola/ADxRay/raw/master/Docs/0.png)

<BR/>

![alt text](https://github.com/ClaudioMerola/ADxRay/raw/master/Docs/1.png)



![alt text](https://github.com/ClaudioMerola/ADxRay/raw/master/Docs/2.png)

<BR/>

![alt text](https://github.com/ClaudioMerola/ADxRay/raw/master/Docs/3.png)

<BR/>

![alt text](https://github.com/ClaudioMerola/ADxRay/raw/master/Docs/4.png)

<BR/>

![alt text](https://github.com/ClaudioMerola/ADxRay/raw/master/Docs/5.png)

<BR/>

![alt text](https://github.com/ClaudioMerola/ADxRay/raw/master/Docs/6.png)
