# Nyanalyzer
A PowerShell analyzer for AzureAD sign-in logs

Usage: ./nyanalyzer.ps1 <input file OR a single email> [number of log samples] [-f] [-debug]
The script accepts up to 4 parameters
The first one is required: could be a list of emails in file, or a single email or an inline list of users "user1, user2"
The second one is optional: define the number of log sample you want to analyze
-f: force the script to get logs from the last 90 days
-debug: debug mode 

This is my very first PS scripts, please don't judge me for its quality.
