# Nyanalyzer
A PowerShell analyzer for AzureAD sign-in logs. It detects abnormal sign-ins and malicious inbox rules.  
The result is quite similar to the built-in AzureAD risky sign-ins alerts as both have similar abnormal activities detection mechanisms I guess (trusted devices based on "statistical").  

Please change the "[CHANGE_ME]" value in the script to yours.

### Prerequisites:
AzureAD Powershell module is required, but it should be installed automatically when the script runs.

### Usage:
```
./nyanalyzer.ps1 <input file OR emails> [number of log samples] [-f] [-debug] [-killEXO] [-keep]
```

The script accepts up to 6 parameters  
The first one is required: could be a list of emails in file, or a single email or an inline list of users "user1, user2"  
The second one is optional: define the number of log sample you want to analyze  
-f: force the script to get logs from the last 90 days  
-debug: debug mode  
-killEXO switch: kill EXO connection without asking, reserved  
-keep switch: keep EXO connection without asking, reserved  

### Sample output:
![image](https://user-images.githubusercontent.com/66635269/114277872-0da9b980-99fb-11eb-881d-f2f68a794cb1.png)
