## Active Directory xRay Script

I started this as a personal project to help me during my day to day work on different Active Directory environments.

The script does not record, create or modify anything in the environment (except for creating a folder named “ADxRay” in C:\ of the computer running the script. Inside that folder the log files and the script main file named “ADxRay_Report(date formated as YEAR-MONTH-DAY).htm” is created). 

The script must be run at a Domain Controller or workstation (see requirements below) running at least Windows Server 2012 / Windows 8. 

The script must be run by a user with Domain Admin privileges (Enterprise Admins if dealing with multiple domains and forests).

#### This script may take several hours to complete!


### How to run:

Just copy or download the ADxRay.ps1 and run on any computer that meets the requirements below.

### Requirements:

The script must be run with the following requirements:

 - At least Windows Server 2012 / Windows 8
 - RSAT (Remote Server Administration Tools) Installed
 - Internet connection is not required*
 
Internet connection might be use by the script for version validation, but is not a requirement. 




#### Screenshots:




![alt text](https://github.com/Merola132/ADxRay/raw/master/Docs/0.png)



![alt text](https://github.com/Merola132/ADxRay/raw/master/Docs/1.png)



![alt text](https://github.com/Merola132/ADxRay/raw/master/Docs/2.png)



![alt text](https://github.com/Merola132/ADxRay/raw/master/Docs/3.png)



![alt text](https://github.com/Merola132/ADxRay/raw/master/Docs/4.png)




![alt text](https://github.com/Merola132/ADxRay/raw/master/Docs/5.png)



![alt text](https://github.com/Merola132/ADxRay/raw/master/Docs/6.png)
