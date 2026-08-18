/* ================= CURATED ALERT METADATA ================= */
const ALERTMETA={
 "1102": {
  "sev": "critical",
  "cadence": {
   "sched": "realtime",
   "window": null,
   "throttle": null
  },
  "supp": false,
  "suppNote": "NEVER baseline-suppress — every log-clear is investigate-now",
  "alertKeys": [
   "ComputerName"
  ],
  "baseKeys": [],
  "deviates": true,
  "cadenceNote": "REAL-TIME, no throttle, no suppression — page on every occurrence",
  "triage": [
   "Rebuild the pre-clear timeline from off-host forwarded logs immediately",
   "Join SubjectLogonId → 4624 for who cleared it and from where",
   "Check 4688 for wevtutil cl / Clear-EventLog just prior"
  ]
 },
 "4624": {
  "sev": "medium",
  "cadence": {
   "sched": "15m",
   "window": "-20m@m",
   "throttle": "4h"
  },
  "supp": true,
  "alertKeys": [
   "Target_User_Name",
   "IpAddress"
  ],
  "baseKeys": [
   "Target_User_Name",
   "IpAddress",
   "Logon_Type"
  ],
  "deviates": false,
  "triage": [
   "Pivot on Target_Logon_ID into 4688 to see what ran in the session",
   "Check 4625 from the same IpAddress for failures preceding this success",
   "Confirm the source IP belongs to a sanctioned jump host / VPN range"
  ]
 },
 "4625": {
  "sev": "medium",
  "cadence": {
   "sched": "15m",
   "window": "-20m@m",
   "throttle": "1h"
  },
  "supp": true,
  "alertKeys": [
   "IpAddress"
  ],
  "baseKeys": [
   "IpAddress"
  ],
  "deviates": true,
  "cadenceNote": "1h throttle by source IP (spray bursts re-alert faster than 4h)",
  "triage": [
   "Group by IpAddress — one source hitting many accounts is spray",
   "Check whether a 4624 success follows from the same IpAddress",
   "Look for a 4740 lockout on the targeted accounts"
  ]
 },
 "4657": {
  "sev": "high",
  "cadence": {
   "sched": "15m",
   "window": "-20m@m",
   "throttle": "4h"
  },
  "supp": true,
  "alertKeys": [
   "ComputerName",
   "Object_Name"
  ],
  "baseKeys": [
   "Object_Name",
   "New_Value"
  ],
  "deviates": false,
  "triage": [
   "Inspect New_Value for a binary path in temp/appdata/public",
   "Pivot Subject_Logon_ID → 4688 to see which process wrote the key",
   "Confirm whether an installer/GPO legitimately owns this key"
  ]
 },
 "4663": {
  "sev": "medium",
  "cadence": {
   "sched": "15m",
   "window": "-20m@m",
   "throttle": "4h"
  },
  "supp": true,
  "alertKeys": [
   "ComputerName",
   "Object_Name"
  ],
  "baseKeys": [
   "Process_Name",
   "Object_Name"
  ],
  "deviates": false,
  "triage": [
   "Check Process_Name — a non-backup, non-AV process on SAM/NTDS.dit is critical",
   "Decode Access_Mask (0x2 write, 0x10 delete) for intent",
   "Correlate to backup/AV windows before escalating"
  ]
 },
 "4672": {
  "sev": "high",
  "cadence": {
   "sched": "15m",
   "window": "-20m@m",
   "throttle": "4h"
  },
  "supp": true,
  "alertKeys": [
   "ComputerName",
   "SubjectUserName"
  ],
  "baseKeys": [
   "SubjectUserName"
  ],
  "deviates": false,
  "triage": [
   "Look for SeDebugPrivilege / SeImpersonatePrivilege in PrivilegeList",
   "Join SubjectLogonId → 4624 for source IP and logon type",
   "Confirm the account is expected to hold admin rights on this host"
  ]
 },
 "4688": {
  "sev": "high",
  "cadence": {
   "sched": "15m",
   "window": "-20m@m",
   "throttle": "4h"
  },
  "supp": true,
  "alertKeys": [
   "ComputerName",
   "New_Process_Name"
  ],
  "baseKeys": [
   "Creator_Process_Name",
   "New_Process_Name"
  ],
  "deviates": false,
  "triage": [
   "Read Process_Command_Line for encoding, discovery, or vssadmin/wbadmin",
   "Check Creator_Process_Name — Office/web parents are the red flag",
   "Pivot Subject_Logon_ID → 4624 for the source IP and logon type"
  ]
 },
 "4698": {
  "sev": "high",
  "cadence": {
   "sched": "15m",
   "window": "-20m@m",
   "throttle": "4h"
  },
  "supp": true,
  "alertKeys": [
   "ComputerName",
   "Task_Name"
  ],
  "baseKeys": [
   "task_cmd"
  ],
  "deviates": false,
  "triage": [
   "Read the extracted task_cmd for temp/appdata paths or encoding",
   "Pivot to 4688 for schtasks.exe / PowerShell / WMI as the creator",
   "Match against known software-update task names"
  ]
 },
 "4719": {
  "sev": "high",
  "cadence": {
   "sched": "15m",
   "window": "-20m@m",
   "throttle": "4h"
  },
  "supp": true,
  "alertKeys": [
   "ComputerName",
   "Category"
  ],
  "baseKeys": [
   "Category",
   "SubjectUserName"
  ],
  "deviates": false,
  "triage": [
   "Confirm which Category was disabled — Process Creation/Logon are severe",
   "Pivot to 4688 for the process that changed policy",
   "Rule out a GPO baseline push in a change window"
  ]
 },
 "4720": {
  "sev": "high",
  "cadence": {
   "sched": "15m",
   "window": "-20m@m",
   "throttle": "4h"
  },
  "supp": true,
  "alertKeys": [
   "ComputerName",
   "Target_User_Name"
  ],
  "baseKeys": [
   "SubjectUserName"
  ],
  "deviates": false,
  "triage": [
   "Check for a 4732 group-add on the new account within minutes",
   "Join to 4624 for the creating session's source IP",
   "Match Target_User_Name against your provisioning naming scheme"
  ]
 },
 "4732": {
  "sev": "high",
  "cadence": {
   "sched": "15m",
   "window": "-20m@m",
   "throttle": "4h"
  },
  "supp": true,
  "alertKeys": [
   "ComputerName",
   "Group_Name"
  ],
  "baseKeys": [
   "Group_Name",
   "SubjectUserName"
  ],
  "deviates": false,
  "triage": [
   "Confirm Group_Name — Administrators/Remote Desktop Users are priority",
   "Check if MemberName was created moments earlier (4720)",
   "Tie to a documented access request before closing"
  ]
 },
 "4740": {
  "sev": "medium",
  "cadence": {
   "sched": "hourly",
   "window": "-60m@m",
   "throttle": "4h"
  },
  "supp": false,
  "suppNote": "lockouts are already aggregated and rare — alert on all, don't baseline-suppress",
  "alertKeys": [
   "Target_User_Name"
  ],
  "baseKeys": [],
  "deviates": true,
  "cadenceNote": "hourly (lockouts aren't time-critical and cluster)",
  "triage": [
   "Pull CallerComputerName sources for the bad attempts",
   "Correlate to 4625 for the failure reasons and IPs",
   "Multiple accounts locked at once = spray, single = likely forgotten password"
  ]
 },
 "4769": {
  "sev": "medium",
  "cadence": {
   "sched": "hourly",
   "window": "-60m@m",
   "throttle": "4h"
  },
  "supp": true,
  "alertKeys": [
   "Account_Name"
  ],
  "baseKeys": [
   "Service_Name"
  ],
  "deviates": true,
  "cadenceNote": "hourly, DC-sourced (roasting shows over minutes-hours, not seconds)",
  "triage": [
   "Confirm Ticket_Encryption_Type 0x17 (RC4) is the roasting signature",
   "Count unique Service_Name per Account_Name — a sweep hits many SPNs",
   "Pivot Client_Address → 4688 for Rubeus/PowerShell on the source"
  ]
 },
 "5140": {
  "sev": "medium",
  "cadence": {
   "sched": "15m",
   "window": "-20m@m",
   "throttle": "4h"
  },
  "supp": true,
  "alertKeys": [
   "ComputerName",
   "Share_Name"
  ],
  "baseKeys": [
   "Share_Name",
   "IpAddress"
  ],
  "deviates": false,
  "triage": [
   "Admin shares (C$/ADMIN$) from a non-management host = lateral movement",
   "Confirm the source IpAddress against sanctioned admin origins",
   "Pivot to 5145 for the specific files touched in the share"
  ]
 },
 "5145": {
  "sev": "medium",
  "cadence": {
   "sched": "15m",
   "window": "-20m@m",
   "throttle": "4h"
  },
  "supp": true,
  "alertKeys": [
   "IpAddress",
   "SubjectUserName"
  ],
  "baseKeys": [
   "Share_Name",
   "SubjectUserName"
  ],
  "deviates": false,
  "triage": [
   "Hundreds of files in minutes = bulk collection (T1039)",
   "Check for sensitive types (.kdbx/.pfx/config) in Relative_Target_Name",
   "Pivot to 4688 on the source for archiving tools (rar/7z)"
  ]
 },
 "5156": {
  "sev": "medium",
  "cadence": {
   "sched": "15m",
   "window": "-20m@m",
   "throttle": "6h"
  },
  "supp": true,
  "alertKeys": [
   "Application_Name",
   "Dest_Address"
  ],
  "baseKeys": [
   "Application_Name",
   "Dest_Address",
   "Dest_Port"
  ],
  "deviates": true,
  "cadenceNote": "6h throttle (very high volume; beaconing is steady, not bursty)",
  "triage": [
   "System binaries (svchost/lsass) to external hosts = injected C2",
   "Look for regular-interval connections — beaconing",
   "Pivot Application_Name → 4688 for the process that opened it"
  ]
 },
 "7045": {
  "sev": "high",
  "cadence": {
   "sched": "15m",
   "window": "-20m@m",
   "throttle": "4h"
  },
  "supp": true,
  "alertKeys": [
   "ComputerName",
   "ServiceName"
  ],
  "baseKeys": [
   "ServiceName",
   "ImagePath"
  ],
  "deviates": false,
  "triage": [
   "ImagePath in temp/appdata/random location is the key IOC",
   "Driver ServiceType = kernel-level persistence, escalate",
   "Pivot to 4688 for sc.exe/PsExec/PowerShell as the installer"
  ]
 },
 "ConsoleLogin": {
  "sev": "medium",
  "cadence": {
   "sched": "15m",
   "window": "-20m@m",
   "throttle": "4h"
  },
  "supp": true,
  "alertKeys": [
   "user",
   "sourceIPAddress"
  ],
  "baseKeys": [
   "user",
   "sourceIPAddress"
  ],
  "deviates": false,
  "triage": [
   "Root login or MFAUsed=No are the escalation triggers",
   "Geolocate sourceIPAddress against expected admin regions",
   "Check for an AssumeRole/CreateAccessKey right after the login"
  ]
 },
 "AssumeRole": {
  "sev": "medium",
  "cadence": {
   "sched": "15m",
   "window": "-20m@m",
   "throttle": "4h"
  },
  "supp": true,
  "alertKeys": [
   "caller",
   "role"
  ],
  "baseKeys": [
   "caller",
   "role"
  ],
  "deviates": false,
  "triage": [
   "Generic/randomized roleSessionName suggests scripted use",
   "Cross-account assumption from an unknown account is high priority",
   "Watch for AttachRolePolicy on the assumed role next"
  ]
 },
 "CreateUser": {
  "sev": "high",
  "cadence": {
   "sched": "15m",
   "window": "-20m@m",
   "throttle": "4h"
  },
  "supp": true,
  "alertKeys": [
   "creator",
   "newUser"
  ],
  "baseKeys": [
   "creator"
  ],
  "deviates": false,
  "triage": [
   "Check for CreateAccessKey on the new user within minutes",
   "CLI userAgent from an external IP raises priority",
   "Match newUser against your provisioning pipeline naming"
  ]
 },
 "CreateAccessKey": {
  "sev": "high",
  "cadence": {
   "sched": "15m",
   "window": "-20m@m",
   "throttle": "4h"
  },
  "supp": true,
  "alertKeys": [
   "creator",
   "target"
  ],
  "baseKeys": [
   "creator",
   "target"
  ],
  "deviates": false,
  "triage": [
   "creator != target (key made for another user) is impersonation setup",
   "Track the returned accessKeyId in subsequent API calls",
   "Confirm against key-rotation automation"
  ]
 },
 "AttachRolePolicy": {
  "sev": "high",
  "cadence": {
   "sched": "15m",
   "window": "-20m@m",
   "throttle": "4h"
  },
  "supp": true,
  "alertKeys": [
   "role",
   "policy"
  ],
  "baseKeys": [
   "role",
   "policy"
  ],
  "deviates": false,
  "triage": [
   "AdministratorAccess/*/FullAccess on a role is the trigger",
   "Check if the role was assumed immediately after (AssumeRole)",
   "Rule out a known IaC pipeline attaching documented policies"
  ]
 },
 "StopLogging": {
  "sev": "high",
  "cadence": {
   "sched": "realtime",
   "window": null,
   "throttle": null
  },
  "supp": false,
  "suppNote": "NEVER suppress — treat every StopLogging/DeleteTrail as investigate-now",
  "alertKeys": [
   "actor",
   "trail"
  ],
  "baseKeys": [],
  "deviates": true,
  "cadenceNote": "REAL-TIME via CloudWatch alarm backstop — no throttle, no suppression",
  "triage": [
   "List every API call by the actor in the 30 min AFTER the gap",
   "Confirm no approved change window covers this",
   "Check for IAM changes (CreateUser/AttachRolePolicy) after logging stopped"
  ]
 },
 "GetSecretValue": {
  "sev": "high",
  "cadence": {
   "sched": "15m",
   "window": "-20m@m",
   "throttle": "4h"
  },
  "supp": true,
  "alertKeys": [
   "caller",
   "sourceIPAddress"
  ],
  "baseKeys": [
   "caller"
  ],
  "deviates": false,
  "triage": [
   "unique_secrets > 3 in the window = dumping, not app use",
   "Confirm caller is the identity normally bound to those secrets",
   "External sourceIPAddress or off-hours raises priority"
  ]
 },
 "ListBuckets": {
  "sev": "medium",
  "cadence": {
   "sched": "15m",
   "window": "-20m@m",
   "throttle": "4h"
  },
  "supp": true,
  "alertKeys": [
   "caller",
   "sourceIPAddress"
  ],
  "baseKeys": [
   "caller"
  ],
  "deviates": false,
  "suppBaseFix": true,
  "triage": [
   "GetCallerIdentity then broad List/Describe = orientation after compromise",
   "Confirm caller isn't a known CSPM/inventory scanner",
   "Watch for GetObject bulk download following enumeration"
  ]
 },
 "GetObject": {
  "sev": "high",
  "cadence": {
   "sched": "15m",
   "window": "-20m@m",
   "throttle": "4h"
  },
  "supp": true,
  "alertKeys": [
   "caller",
   "sourceIPAddress"
  ],
  "baseKeys": [
   "caller",
   "bucket"
  ],
  "deviates": false,
  "triage": [
   "objects > 200 in minutes = bulk pull (T1530)",
   "External sourceIPAddress = probable exfil (T1048)",
   "Confirm caller normally reads this bucket at all"
  ]
 }
};
