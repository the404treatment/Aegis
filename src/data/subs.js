/* ================= MITRE TECHNIQUES (with mitigations) ================= */

/* Named sub-techniques for the parents an AD/Windows/CloudTrail SOC hits most.
   Parents not listed here are tracked at parent level with a count only. */
const SUBS={
 "T1059":[["T1059.001","PowerShell"],["T1059.003","Windows Command Shell"],["T1059.005","Visual Basic"],["T1059.007","JavaScript"],["T1059.006","Python"]],
 "T1003":[["T1003.001","LSASS Memory"],["T1003.002","Security Account Manager"],["T1003.003","NTDS"],["T1003.004","LSA Secrets"],["T1003.006","DCSync"]],
 "T1021":[["T1021.001","Remote Desktop Protocol"],["T1021.002","SMB/Windows Admin Shares"],["T1021.003","Distributed Component Object Model"],["T1021.004","SSH"],["T1021.006","Windows Remote Management"]],
 "T1053":[["T1053.005","Scheduled Task"],["T1053.002","At"],["T1053.003","Cron"],["T1053.006","Systemd Timers"]],
 "T1543":[["T1543.003","Windows Service"],["T1543.001","Launch Agent"],["T1543.002","Systemd Service"],["T1543.004","Launch Daemon"]],
 "T1547":[["T1547.001","Registry Run Keys / Startup Folder"],["T1547.004","Winlogon Helper DLL"],["T1547.009","Shortcut Modification"],["T1547.014","Active Setup"]],
 "T1546":[["T1546.003","WMI Event Subscription"],["T1546.008","Accessibility Features"],["T1546.011","Application Shimming"],["T1546.012","Image File Execution Options Injection"],["T1546.015","Component Object Model Hijacking"]],
 "T1558":[["T1558.003","Kerberoasting"],["T1558.001","Golden Ticket"],["T1558.002","Silver Ticket"],["T1558.004","AS-REP Roasting"]],
 "T1550":[["T1550.002","Pass the Hash"],["T1550.003","Pass the Ticket"],["T1550.001","Application Access Token"],["T1550.004","Web Session Cookie"]],
 "T1078":[["T1078.001","Default Accounts"],["T1078.002","Domain Accounts"],["T1078.003","Local Accounts"],["T1078.004","Cloud Accounts"]],
 "T1566":[["T1566.001","Spearphishing Attachment"],["T1566.002","Spearphishing Link"],["T1566.003","Spearphishing via Service"],["T1566.004","Spearphishing Voice"]],
 "T1070":[["T1070.001","Clear Windows Event Logs"],["T1070.004","File Deletion"],["T1070.006","Timestomp"],["T1070.003","Clear Command History"]],
 "T1562":[["T1562.001","Disable or Modify Tools"],["T1562.002","Disable Windows Event Logging"],["T1562.004","Disable or Modify System Firewall"],["T1562.008","Disable or Modify Cloud Logs"]],
 "T1055":[["T1055.001","Dynamic-link Library Injection"],["T1055.002","Portable Executable Injection"],["T1055.012","Process Hollowing"],["T1055.003","Thread Execution Hijacking"]],
 "T1552":[["T1552.001","Credentials In Files"],["T1552.002","Credentials in Registry"],["T1552.004","Private Keys"],["T1552.005","Cloud Instance Metadata API"]],
 "T1555":[["T1555.003","Credentials from Web Browsers"],["T1555.004","Windows Credential Manager"],["T1555.005","Password Managers"]],
 "T1098":[["T1098.001","Additional Cloud Credentials"],["T1098.002","Additional Email Delegate Permissions"],["T1098.003","Additional Cloud Roles"]],
 "T1136":[["T1136.001","Local Account"],["T1136.002","Domain Account"],["T1136.003","Cloud Account"]],
 "T1087":[["T1087.001","Local Account"],["T1087.002","Domain Account"],["T1087.004","Cloud Account"]],
 "T1069":[["T1069.001","Local Groups"],["T1069.002","Domain Groups"],["T1069.003","Cloud Groups"]],
 "T1218":[["T1218.011","Rundll32"],["T1218.010","Regsvr32"],["T1218.005","Mshta"],["T1218.007","Msiexec"]],
 "T1548":[["T1548.002","Bypass User Account Control"],["T1548.001","Setuid and Setgid"],["T1548.003","Sudo and Sudo Caching"]],
 "T1110":[["T1110.001","Password Guessing"],["T1110.002","Password Cracking"],["T1110.003","Password Spraying"],["T1110.004","Credential Stuffing"]],
 "T1071":[["T1071.001","Web Protocols"],["T1071.004","DNS"],["T1071.002","File Transfer Protocols"]],
 "T1048":[["T1048.003","Exfiltration Over Unencrypted Non-C2 Protocol"],["T1048.002","Exfiltration Over Asymmetric Encrypted Non-C2 Protocol"]],
 "T1567":[["T1567.002","Exfiltration to Cloud Storage"],["T1567.001","Exfiltration to Code Repository"]],
 "T1090":[["T1090.001","Internal Proxy"],["T1090.002","External Proxy"],["T1090.003","Multi-hop Proxy"],["T1090.004","Domain Fronting"]]
};
