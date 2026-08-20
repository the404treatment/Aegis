/* ================= DATA: WINDOWS EVENTS ================= */
const WIN=[
 {id:"4624",title:"Successful logon",cat:"auth",risk:"med",desc:"An account successfully logged on to this host",
  mitre:["T1078","T1021","T1133","T1550"],
  setup:"On by default (Audit Logon). Forward WinEventLog:Security to Splunk via Universal Forwarder + inputs.conf.",
  fields:[["Logon_Type","2=Interactive, 3=Network, 10=RemoteInteractive - types 3/10 from unexpected sources are critical"],["Target_User_Name","Account that logged on - service accounts logging in interactively are suspicious"],["IpAddress","Source IP - external IPs or unexpected internal ranges are red flags"],["Target_Logon_ID","Session ID - correlate to 4688 Subject_Logon_ID to link logons to process execution"],["Authentication_Package","NTLM vs Kerberos - NTLM on internal Kerberos-capable hosts may indicate pass-the-hash (T1550)"]],
  corr:[["4688","Link Target_Logon_ID → Subject_Logon_ID to see processes run in this session"],["4625","Failures before this success? Brute force or credential stuffing"],["4672","Was this logon assigned special (admin) privileges?"]],
  iocs:[["r","Logon type 3 or 10 from external IPs"],["r","Service account with interactive logon (type 2)"],["r","NTLM auth for admin accounts - possible pass-the-hash"],["a","Logon outside business hours for this account"],["a","Admin account logon from a workstation instead of a jump host"],["g","Expected admin account from known corporate IP"]],
  benign:["Domain users logging into their own workstations","Service accounts running scheduled tasks","Admin logging on from known jump host"],
  query:`index=* source="WinEventLog:Security" EventCode=4624
| where Logon_Type IN ("3","10")
| where NOT cidrmatch("10.0.0.0/8", IpAddress)
| where NOT cidrmatch("192.168.0.0/16", IpAddress)
| table _time, ComputerName, Target_User_Name,
    IpAddress, Logon_Type, Authentication_Package`},
 {id:"4625",title:"Failed logon",cat:"auth",risk:"med",desc:"An account failed to log on - authentication rejected",
  mitre:["T1110","T1078"],
  setup:"On by default (Audit Logon). Forward WinEventLog:Security.",
  fields:[["Target_User_Name","Account being attacked - admin accounts are high priority"],["Sub_Status","0xC000006A=wrong password, 0xC0000064=no such user, 0xC000015B=logon type not granted"],["IpAddress","Source of failed attempt - spray pattern from one IP"],["Logon_Type","3=Network, 10=RemoteInteractive"],["Failure_Reason","Text description of the failure"]],
  corr:[["4624","Did a success follow the failures from the same source?"],["4740","Did the account lock out after these failures?"]],
  iocs:[["r","High-volume failures from one IP across many accounts - password spray"],["r","Failures on admin or service accounts from external IPs"],["a","Multiple failures on one account then success - brute force hit"],["a","Sub_Status 0xC000006A with valid username - password guessing"],["g","Single user, single failure - mistyped password"]],
  benign:["User mistyping password after leave","Mobile device with stale cached credentials","Service account with expired password"],
  query:`index=* source="WinEventLog:Security" EventCode=4625
| stats count as failures, dc(Target_User_Name) as accounts,
    values(Sub_Status) as error_codes
    by IpAddress, _time span=10m
| where failures > 5 OR accounts > 3
| sort - failures`},
 {id:"4688",title:"New process created",cat:"process",risk:"high",desc:"A new process was spawned - the workhorse detection event",
  mitre:["T1059","T1204","T1047","T1218","T1027","T1036","T1087","T1082","T1069","T1018","T1105","T1560","T1490","T1489"],
  setup:"GPO → Advanced Audit Policy → Detailed Tracking → Audit Process Creation, PLUS Admin Templates → System → Audit Process Creation → 'Include command line' (essential).",
  fields:[["New_Process_Name","Binary launched - is it expected on this host?"],["Creator_Process_Name","Parent process - what spawned it? Office→PowerShell is a classic"],["Process_Command_Line","Full arguments - encoded commands, discovery commands, vssadmin delete"],["SubjectUserName","Account that triggered the process"],["Subject_Logon_ID","Session ID - correlate to 4624 for source IP"]],
  corr:[["4624","Subject_Logon_ID → Target_Logon_ID for source IP and logon type"],["4663","Did that process access sensitive files or registry keys?"],["7045","Did it install a new service?"]],
  iocs:[["r","cmd/powershell spawned by web server or Office apps"],["r","vssadmin delete shadows / wbadmin delete - pre-ransomware (T1490)"],["r","certutil/bitsadmin downloading files (T1105)"],["r","whoami, net group, nltest bursts - discovery sweep (T1087/T1082)"],["a","Encoded command line (-EncodedCommand, base64) - T1027"],["a","System binary from wrong path - masquerading (T1036)"],["g","Known admin tools by admin accounts in business hours"]],
  benign:["AV scan processes spawned from AV service","Software updates from vendor directories","Scheduled maintenance scripts"],
  query:`index=* source="WinEventLog:Security" EventCode=4688
| where match(New_Process_Name,"(?i)cmd\\.exe|powershell|wscript|cscript|mshta|regsvr32|rundll32|certutil|bitsadmin|vssadmin|wbadmin|whoami|nltest")
| where NOT match(Creator_Process_Name,"(?i)services\\.exe|taskhost|svchost")
| table _time, ComputerName, SubjectUserName,
    Creator_Process_Name, New_Process_Name, Process_Command_Line`},
 {id:"4657",title:"Registry value modified",cat:"registry",risk:"high",desc:"A registry value was created or changed - persistence and evasion",
  mitre:["T1547","T1543.003","T1546","T1562"],
  setup:"Requires Audit Object Access → Registry, plus SACLs applied to target keys (Run, Services, AutoLogger). auditpol /set /subcategory:\"Registry\" /success:enable",
  fields:[["Object_Name","Full registry key path - Run/RunOnce keys are critical"],["New_Value","The data written - binary paths in suspicious locations"],["Object_Value_Name","Name of the value being set"],["SubjectUserName","Account making the change"],["Subject_Logon_ID","Session ID - tie back to the process"]],
  corr:[["4688","What process made the modification - via Subject_Logon_ID"],["4624","What session does this belong to?"]],
  iocs:[["r","Write to HKLM\\...\\CurrentVersion\\Run or RunOnce"],["r","New value pointing to a binary in temp/appdata/public"],["r","Modification to ETW AutoLogger or EventLog service keys"],["a","Changes to service ImagePath keys for existing services"],["a","Image File Execution Options debugger set - T1546"],["g","Vendor software writing known installation values"]],
  benign:["Installers writing app launch keys","Group Policy preferences updating registry","AV updating its configuration keys"],
  query:`index=* source="WinEventLog:Security" EventCode=4657
| where match(Object_Name,"(?i)CurrentVersion\\\\Run|Services\\\\.*\\\\ImagePath|AutoLogger|Image File Execution Options")
| table _time, ComputerName, SubjectUserName,
    Object_Name, Object_Value_Name, New_Value`},
 {id:"4663",title:"Object access attempt",cat:"object",risk:"med",desc:"Attempted access to a file, folder, or registry key (auditing required)",
  mitre:["T1552","T1003","T1555","T1486","T1005","T1562"],
  setup:"Requires Audit Object Access → File System + SACLs on sensitive paths (SAM, NTDS.dit, credential stores). High volume - scope SACLs tightly.",
  fields:[["Object_Name","Path of file or registry key accessed"],["Access_Mask","0x2=Write, 0x10=Delete, 0x1=ReadData"],["Process_Name","Process opening the object"],["SubjectUserName","Account performing access"],["Subject_Logon_ID","Session ID - correlate to source logon"]],
  corr:[["4688","Which process accessed this - via Process_Name"],["4624","What logon session owns this activity?"]],
  iocs:[["r","Access to SAM, NTDS.dit, lsass, or credential files (T1003)"],["r","Browser credential stores read by non-browser processes (T1555)"],["r","Mass delete access across files in a short window - ransomware (T1486)"],["a","Unusual process reading certificate stores"],["g","AV or backup agents in normal operations"]],
  benign:["Backup software during backup window","AV scanning files on write","Indexing services scanning documents"],
  query:`index=* source="WinEventLog:Security" EventCode=4663
| where match(Object_Name,"(?i)sam|ntds\\.dit|\\\\lsass|credentials|Login Data|AutoLogger|EventLog")
| table _time, ComputerName, SubjectUserName,
    Process_Name, Object_Name, Access_Mask`},
 {id:"4672",title:"Special privileges assigned",cat:"privilege",risk:"high",desc:"Admin-equivalent privileges assigned to a new logon session",
  mitre:["T1078","T1548"],
  setup:"On by default (Audit Special Logon). Forward WinEventLog:Security.",
  fields:[["SubjectUserName","Account assigned the privileges"],["PrivilegeList","SeDebugPrivilege / SeImpersonatePrivilege are critical"],["SubjectLogonId","Join to 4624 for source IP and logon context"]],
  corr:[["4624","Join SubjectLogonId for IP, logon type, auth package"],["4688","What ran under this privileged session?"]],
  iocs:[["r","Admin logon from workstation or unexpected IP"],["r","SeDebugPrivilege assigned - lsass injection capability"],["a","Privileged session outside maintenance windows"],["g","Domain admin from known jump host in change window"]],
  benign:["Approved maintenance by domain admin","Backup tooling using expected privileged accounts"],
  query:`index=* source="WinEventLog:Security" EventCode=4672
| join SubjectLogonId
  [search EventCode=4624 | fields SubjectLogonId, IpAddress, Logon_Type]
| table _time, ComputerName, SubjectUserName,
    PrivilegeList, IpAddress, Logon_Type`},
 {id:"4698",title:"Scheduled task created",cat:"persistence",risk:"high",desc:"A new scheduled task was created - classic persistence",
  mitre:["T1053","T1547"],
  setup:"Enable Audit Other Object Access Events (Advanced Audit Policy → Object Access).",
  fields:[["Task_Name","Often mimics system tasks with subtle variations"],["TaskContent","XML blob - extract the <Command> action"],["SubjectUserName","Account that created the task"],["Subject_Logon_ID","Tie to the creating process and logon"]],
  corr:[["4688","schtasks.exe, PowerShell, or WMI as creator?"],["4624","What session owns the creation?"]],
  iocs:[["r","Task command in temp/appdata or encoded"],["r","Created by non-admin or from a remote session"],["r","Name mimicking \\Microsoft\\Windows\\ system tasks"],["a","Created outside business hours"],["g","Known installer creating a maintenance task"]],
  benign:["Software auto-update tasks","IT automation maintenance tasks","AV scan scheduling at install"],
  query:`index=* source="WinEventLog:Security" EventCode=4698
| eval task_cmd=replace(TaskContent,".*<Command>(.*?)</Command>.*","\\1")
| where NOT match(task_cmd,"(?i)c:\\\\windows\\\\system32|c:\\\\program files")
| table _time, ComputerName, SubjectUserName, Task_Name, task_cmd`},
 {id:"4719",title:"Audit policy changed",cat:"defense",risk:"high",desc:"System audit policy changed - attackers disable logging first",
  mitre:["T1562","T1562.002"],
  setup:"On by default (Audit Policy Change). Forward WinEventLog:Security.",
  fields:[["AuditPolicyChanges","Enabled or disabled - disabled is the key signal"],["Category","Process Creation, Logon are critical categories"],["SubjectUserName","Account that changed the policy"],["SubCategoryGuid","Specific sub-category GUID"]],
  corr:[["4688","What process made the change?"],["4657","Were registry-based audit keys also modified?"]],
  iocs:[["r","Auditing disabled for Process Creation, Logon, or Object Access"],["r","Change immediately before an attack chain begins"],["a","Change outside a management window"],["g","Group Policy applying known audit baseline"]],
  benign:["GPO updating audit policy to baseline","Admin applying CIS/DISA benchmark"],
  query:`index=* source="WinEventLog:Security" EventCode=4719
| where match(AuditPolicyChanges,"(?i)removed|no auditing")
| table _time, ComputerName, SubjectUserName,
    Category, AuditPolicyChanges`},
 {id:"4720",title:"User account created",cat:"account",risk:"high",desc:"A new user account was created - post-compromise persistence",
  mitre:["T1136","T1078","T1098"],
  setup:"On by default (Audit User Account Management). Forward WinEventLog:Security from DCs and servers.",
  fields:[["Target_User_Name","Name of the new account"],["SubjectUserName","Who created it"],["Subject_Logon_ID","Session ID - find source IP and process"],["Target_Domain_Name","Domain of creation"]],
  corr:[["4624","Where did the creating session originate?"],["4688","net.exe? PowerShell? What created it?"],["4732","Added to a privileged group immediately after?"]],
  iocs:[["r","Account created then immediately added to Administrators"],["r","Created by a non-admin or unexpected user"],["r","Name mimicking a service or built-in account"],["a","Created outside business hours"],["g","IT admin with matching change request"]],
  benign:["Helpdesk onboarding","Automated provisioning pipelines","Service accounts via software deployment"],
  query:`index=* source="WinEventLog:Security" EventCode=4720
| join Subject_Logon_ID
  [search EventCode=4624 | fields Target_Logon_ID as Subject_Logon_ID, IpAddress]
| table _time, ComputerName, Target_User_Name,
    SubjectUserName, IpAddress`},
 {id:"4732",title:"Member added to local group",cat:"account",risk:"high",desc:"Account added to a security-enabled local group - privilege grant",
  mitre:["T1098","T1136"],
  setup:"On by default (Audit Security Group Management). Forward WinEventLog:Security.",
  fields:[["Group_Name","Administrators / Remote Desktop Users are the critical groups"],["MemberName","Account that was added (DN or SID)"],["SubjectUserName","Who performed the addition"],["Subject_Logon_ID","Session - trace back to source"]],
  corr:[["4720","Was the member account created moments before?"],["4624","Which session performed the change?"],["4688","net localgroup or PowerShell as the tool?"]],
  iocs:[["r","Addition to Administrators outside change windows"],["r","Freshly created account added to a privileged group"],["a","Addition to Remote Desktop Users on servers"],["g","Documented access request fulfilled by IT"]],
  benign:["Approved access grants by helpdesk","Provisioning automation"],
  query:`index=* source="WinEventLog:Security" EventCode=4732
| where match(Group_Name,"(?i)admin|remote desktop|backup operators")
| table _time, ComputerName, SubjectUserName,
    MemberName, Group_Name`},
 {id:"4740",title:"Account locked out",cat:"account",risk:"med",desc:"Account locked from too many failed authentication attempts",
  mitre:["T1110"],
  setup:"On by default (Audit Account Lockout). Collect from domain controllers.",
  fields:[["Target_User_Name","Locked account"],["CallerComputerName","Machine generating the bad attempts"],["Target_Domain_Name","Domain of the locked account"]],
  corr:[["4625","Failure reasons and source IPs for the attempts"],["4624","Success preceding or following the lockout?"]],
  iocs:[["r","Multiple accounts locked simultaneously - spray"],["r","High-value account locked from unexpected source"],["a","Single account locked from multiple sources"],["g","Single user, single machine - forgotten password"]],
  benign:["Forgotten password after leave","Service with stale credentials","Mobile device with cached old creds"],
  query:`index=* source="WinEventLog:Security" EventCode=4740
| stats count, values(CallerComputerName) as sources
    by Target_User_Name, Target_Domain_Name
| where count > 1 | sort - count`},
 {id:"4769",title:"Kerberos service ticket",cat:"auth",risk:"med",desc:"Service ticket requested - kerberoasting shows as RC4 bursts",
  mitre:["T1558"],
  setup:"Audit Kerberos Service Ticket Operations on domain controllers only - collect DC Security logs.",
  fields:[["Service_Name","SPN requested - many unique SPNs from one user = roasting sweep"],["Ticket_Encryption_Type","0x17 (RC4) requests are the kerberoasting signature"],["Account_Name","Requesting account"],["Client_Address","Source of the request"]],
  corr:[["4624","What session is the requesting account running?"],["4688","Rubeus/PowerShell on the source host?"]],
  iocs:[["r","Burst of 0x17 tickets across many unique services from one account"],["r","Service accounts requesting tickets for unrelated SPNs"],["a","RC4 tickets in an AES-hardened domain"],["g","Legacy app with documented RC4 dependency"]],
  benign:["Legacy applications pinned to RC4","Vulnerability scanners enumerating SPNs (verify source)"],
  query:`index=* source="WinEventLog:Security" EventCode=4769
| where Ticket_Encryption_Type="0x17"
| stats count as requests, dc(Service_Name) as unique_services
    by Account_Name, Client_Address, _time span=10m
| where unique_services > 5
| sort - unique_services`},
 {id:"5140",title:"Network share accessed",cat:"network",risk:"med",desc:"A network share was accessed - once per session",
  mitre:["T1021","T1039","T1570"],
  setup:"Enable Audit File Share (Advanced Audit Policy → Object Access).",
  fields:[["Share_Name","C$ and ADMIN$ are admin shares - high priority"],["IpAddress","Source IP - external is a major red flag"],["SubjectUserName","Accessing account"],["Access_Mask","Type of access requested"]],
  corr:[["5145","Per-file access detail within the share"],["4624","Confirm the source session"],["4688","What process on the source performs the access?"]],
  iocs:[["r","Admin shares from unexpected machines - lateral movement"],["r","Access from external IPs"],["a","Multiple shares in quick succession - enumeration"],["g","Backup or monitoring servers on schedule"]],
  benign:["Backup software in backup window","SCCM software deployment"],
  query:`index=* source="WinEventLog:Security" EventCode=5140
| where match(Share_Name,"(?i)c\\$|admin\\$|ipc\\$")
| where NOT cidrmatch("10.0.0.0/8", IpAddress)
| table _time, ComputerName, Share_Name,
    SubjectUserName, IpAddress`},
 {id:"5145",title:"Detailed share access",cat:"network",risk:"med",desc:"Per-file access within a share - collection & staging visibility",
  mitre:["T1021","T1039","T1005","T1570"],
  setup:"Enable Audit Detailed File Share - very high volume; scope to file servers holding sensitive data.",
  fields:[["Relative_Target_Name","Exact file touched within the share"],["Share_Name","Which share"],["IpAddress","Source machine"],["SubjectUserName","Account - is this their normal data scope?"],["Access_Mask","Read vs write vs delete"]],
  corr:[["5140","Session-level share access context"],["4624","Source logon session"],["4688","Archiving tools (rar/7z) on the source? Staging (T1560)"]],
  iocs:[["r","Hundreds of files read in minutes - bulk collection (T1039)"],["r","Access to .kdbx, .pfx, config, finance files by unusual accounts"],["a","First-time access to a share by an account"],["g","Backup accounts during backup windows"]],
  benign:["Backup jobs enumerating files","DLP or classification scanners"],
  query:`index=* source="WinEventLog:Security" EventCode=5145
| stats count as accesses, dc(Relative_Target_Name) as files
    by IpAddress, SubjectUserName, Share_Name, _time span=15m
| where files > 100
| sort - files`},
 {id:"5156",title:"Network connection allowed",cat:"network",risk:"med",desc:"Windows Filtering Platform permitted a connection",
  mitre:["T1071","T1041","T1190","T1046","T1572","T1090","T1567","T1048","T1595"],
  setup:"Enable Audit Filtering Platform Connection - very high volume; consider scoping to servers/DMZ or sampling.",
  fields:[["Application_Name","Process making the connection"],["Direction","Inbound or Outbound"],["Dest_Address","Destination IP - external is the focus"],["Dest_Port","Unusual ports (4444, 1337, 9001) are suspicious"],["Protocol","6=TCP, 17=UDP"]],
  corr:[["4688","Which process created the connection?"],["4624","Who was logged on at the time?"]],
  iocs:[["r","System binaries (svchost, lsass) to unusual external hosts"],["r","Regular-interval connections - beaconing (T1071)"],["r","Inbound sweeps across many ports - scanning (T1595/T1046)"],["a","High outbound volume to file-sharing / paste sites (T1567)"],["g","Browser/update processes to known vendor IPs"]],
  benign:["AV cloud signature updates","Windows Update to Microsoft CDN"],
  query:`index=* source="WinEventLog:Security" EventCode=5156
| where Direction="Outbound"
| where NOT cidrmatch("10.0.0.0/8", Dest_Address)
| where NOT cidrmatch("192.168.0.0/16", Dest_Address)
| stats count by Application_Name, Dest_Address, Dest_Port
| sort - count`},
 {id:"7045",title:"New service installed",cat:"persistence",risk:"high",desc:"A new Windows service was installed - critical persistence signal",
  mitre:["T1543.003","T1569","T1036"],
  setup:"System log, on by default. Forward WinEventLog:System.",
  fields:[["ServiceName","Compare against known baseline"],["ImagePath","Binary path - suspicious locations are the key IOC"],["ServiceType","Driver installations are especially high risk"],["StartType","Auto-start = persistence; demand = execution"],["AccountName","LocalSystem with unusual binary is critical"]],
  corr:[["4688","sc.exe, PowerShell, or PsExec as installer?"],["4624","What logon preceded the install?"]],
  iocs:[["r","Binary path in temp, appdata, or random-named location"],["r","Name mimicking legitimate services - masquerading (T1036)"],["r","Driver service - kernel-level persistence or rootkit"],["a","Auto-start service by a non-system process"],["g","Known installer creating a documented service"]],
  benign:["AV installing kernel driver services","Enterprise management agents"],
  query:`index=* source="WinEventLog:System" EventCode=7045
| where NOT match(ImagePath,"(?i)c:\\\\windows\\\\system32|c:\\\\program files")
| table _time, ComputerName, ServiceName,
    ImagePath, ServiceType, StartType, AccountName`},
 {id:"1102",title:"Audit log cleared",cat:"defense",risk:"high",desc:"The Security event log was cleared - near-certain hostile action",
  mitre:["T1070","T1562.002"],
  setup:"Always recorded on log clear (cannot be suppressed without stopping the service). CRITICAL: forward logs off-host in near-real-time so the clear doesn't destroy evidence.",
  fields:[["SubjectUserName","Account that cleared the log"],["SubjectLogonId","Session - trace the full chain before the clear"],["ComputerName","Host whose evidence was destroyed"]],
  corr:[["4624","What session cleared it, from where?"],["4688","wevtutil cl or Clear-EventLog immediately prior?"]],
  iocs:[["r","ANY 1102 outside documented maintenance is investigate-now"],["r","Clear following other alert activity on the same host"],["a","Cleared by an account that has never done so before"],["g","Documented log rotation by known admin (rare - verify)"]],
  benign:["Deliberate admin log maintenance (should be rare and ticketed)"],
  query:`index=* source="WinEventLog:Security" EventCode=1102
| table _time, ComputerName, SubjectUserName, SubjectLogonId
| eval priority="CRITICAL - investigate immediately"`}
];
