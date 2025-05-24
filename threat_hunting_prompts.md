# Threat Hunting Prompts

## SecOps Hunting

* Show me all failed login attempts from IP address
> Show me all failed login attempts from IP addresses that have not previously authenticated successfully to this system within the past 30 days. Include the source IP, account name, and timestamp.

* Unusual traffic patterns
> Identify unusual network traffic patterns, such as spikes in data transfer or connections to unfamiliar IP addresses in the past 30 days

## Threat Intelligence
* Understanding Malware
> Tell me more about Ransomhub Ransomware. Include their TTPs, threat actors observed to have used them, and any known IOCs first seen in the past 30 days. 

* Understanding Campaigns (Strategic) 
> Based on this report <insert link>, summarise the report for a CISO. Include their TTPs

* Understanding Campaigns + Hunting Packages (Operational / Tactical)
> Based on this report <insert link>, summarise the report for a threat intelligence analyst. Please output the following: - any ttps/behaviours in the report - any indicators / iocs in the report in a table format. If there are any TTPs that we can use, convert them into a cyber threat hunting package based on YARA-L. Leverage Sysmon event data primarily when creating YARA-L rules

