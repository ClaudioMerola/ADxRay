Active Directory Health Check

I started this as a personal project to help me during my work days on customer´s sites and environments. The idea was to compile and put all the manual tests the validations I used to make in the customer´s environment at a simple place in the most automated way as possible. 

The script does not record, create or modify anything in the environment (except for creating a folder named “ADHC” in C:\, and a file named “ADHC_Report.htm”). 

The script must be run at a Domain Controller running at least Windows Server 2012. 

The script must be run by a user with Domain Admin privileges (Enterprise Admins would be better if dealing with multiple domains and forests).

![Header](/Img/0.png)

![Forest](/Img/1.PNG)

![DCs](/Img/2.png)

![DCDIAG](/Img/3.PNG)

![Users](/Img/4.PNG)

![Groups](/Img/5.PNG)

![GPOs](/Img/6.png)
