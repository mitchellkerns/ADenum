# ADenum.py
Enumerate Active Directory using Nessus data.

## Goals, requirements, and limitations
The goal of this project is to help automate some of the initial active directory reconnaissance that you might do at the start of a pentest. Currently the script is setup to execute on a remote system over an SSH connection since that is my current use case, although I intend to add a option to execute it locally in the future. Another requirement currently is to provide a Nessus csv as input when running the script. This is fine if you already use Nessus although I intend to also add an option for running it without the Nessus csv in the future.

The assumption is also that your remote server is running kali linux or another linux distro with the required tools already installed. Furthermore, the goal here isn't to automate the entire pentest but just some of the basic initial recon that you might want to do, where stealth is not a consideration.

## Help Info:
```
PS C:\ADenum> python .\ADenum.py --help
usage: ADenum.py [-h] [--html] [--hostname HOSTNAME] [--username USERNAME] [--password PASSWORD] csv_file

Analyze Nessus CSV and enumerate basic info on Active Directory.

positional arguments:
  csv_file             Path to the Nessus CSV file.

options:
  -h, --help           show this help message and exit
  --html               Generate HTML report.
  --hostname HOSTNAME  Hostname or IP address of the remote system.
  --username USERNAME  Username for SSH connection.
  --password PASSWORD  Password for SSH connection.
```
## Basic Usage:
```
PS C:\ADenum> python .\ADenum.py C:\data\test_scan_1.csv --hostname 192.168.0.10 --user kali --password kali --html
Starting analysis...
Parsing Nessus CSV file...
Enumerating domains using crackmapexec...
Querying DNS for domain controllers...

Displaying results...

DNS Servers:
 - 192.168.0.53
 - 192.168.0.68
 - 192.168.0.200

Kerberos Servers:
 - 192.168.0.200

LDAP Servers:
 - 192.168.0.200

Domains:
 - localdomain
 - vuln-corp.local

Domain Controllers:
 - dc01-2019.vuln-corp.local     192.168.0.200

HTML report generated: C:\data\AD_Report.html
Saving SMB not signed IPs to file...
Hosts with SMB signing not enabled saved to: C:\data\smb_not_signed.txt
```


# Roadmap:

## Current Features:
- Analzyes Nessus CSV and extracts DNS, LDAP, and Kerberos Servers.
- Enumerates all AD domains in your current scope.
- Queries DNS servers to find Domain Controllers (lists IP and FQDN).
- Saves a txt file containing all IPs with SMB signing not enabled (for NTLM relaying).
- Optionally saves your results in a html file.

## To do:
- Make the html better looking.
- Add an option to execute locally.
- Add an option for no nessus csv.
- Add some more security checks against the domain controllers.
- Add more options to enumerate servers and workstations, etc...
