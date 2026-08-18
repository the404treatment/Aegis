
/* ================= DATA: AWS EVENTS ================= */
const AWS=[
 {id:"ConsoleLogin",title:"Console login",cat:"auth",risk:"med",desc:"A user signed into the AWS Management Console",
  mitre:["T1078","T1133","T1110"],
  setup:"Requires CloudTrail enabled (management events). Install the Splunk Add-on for AWS and ingest via SQS-based S3 or CloudWatch Logs.",
  fields:[["userIdentity.userName","IAM user or role that logged in"],["userIdentity.type","Root, IAMUser, AssumedRole — Root is critical"],["sourceIPAddress","Compare to known corporate ranges"],["additionalEventData.MFAUsed","No MFA on admin accounts is a critical finding"]],
  corr:[["AssumeRole","Assumed a more privileged role after login?"],["CreateAccessKey","Created programmatic keys during this session?"]],
  iocs:[["r","Root account login — should almost never happen"],["r","MFAUsed=No for privileged accounts"],["r","Login from unexpected country or IP range"],["a","Login outside normal hours"],["g","Known IAM user from corporate IP with MFA"]],
  benign:["Admins from known office IPs in business hours","Federated automated pipelines"],
  query:`index=* sourcetype=aws:cloudtrail eventName=ConsoleLogin
| eval mfa=spath(_raw,"additionalEventData.MFAUsed")
| eval user=spath(_raw,"userIdentity.userName")
| eval userType=spath(_raw,"userIdentity.type")
| where userType="Root" OR mfa="No"
| table _time, user, userType, sourceIPAddress, mfa`},
 {id:"AssumeRole",title:"Role assumed",cat:"auth",risk:"med",desc:"An entity assumed an IAM role — CI/CD or privilege escalation",
  mitre:["T1078","T1098","T1550"],
  setup:"CloudTrail management events (STS). Ensure sts.amazonaws.com events are captured.",
  fields:[["userIdentity.arn","Who assumed the role"],["requestParameters.roleArn","Which role — is it high privilege?"],["requestParameters.roleSessionName","Generic names suggest scripts"],["sourceIPAddress","External IPs are suspicious"],["errorCode","AccessDenied = probing for valid roles"]],
  corr:[["ConsoleLogin","Console login preceding the assumption?"],["AttachRolePolicy","Policies added to this role?"]],
  iocs:[["r","Cross-account assumption from unknown external accounts"],["r","Generic/randomized session names — script behaviour"],["a","Assumed from unusual region or IP"],["g","Known CI/CD from expected IPs"]],
  benign:["CI/CD deployment roles","Lambda execution roles"],
  query:`index=* sourcetype=aws:cloudtrail eventName=AssumeRole
| eval role=spath(_raw,"requestParameters.roleArn")
| eval caller=spath(_raw,"userIdentity.arn")
| where NOT match(role,"(?i)lambda|codebuild|codepipeline")
| table _time, caller, role, sourceIPAddress, awsRegion`},
 {id:"CreateUser",title:"IAM user created",cat:"iam",risk:"high",desc:"New IAM user created — common post-compromise persistence",
  mitre:["T1136","T1078","T1098"],
  setup:"CloudTrail management events (IAM is global — ensure the global-service-events trail is enabled).",
  fields:[["requestParameters.userName","Newly created user"],["userIdentity.userName","Creator"],["sourceIPAddress","Origin of the API call"],["userAgent","CLI creation is more suspicious than console"],["awsRegion","Unexpected regions are suspicious"]],
  corr:[["CreateAccessKey","Programmatic key immediately created?"],["AttachRolePolicy","Admin policy attached?"]],
  iocs:[["r","User created then immediately given admin policy"],["r","CLI creation from external/unknown IP"],["r","Username mimicking a service account"],["a","Created outside business hours"],["g","Known provisioning automation from expected IP"]],
  benign:["HR provisioning pipeline","Contractor accounts via change management"],
  query:`index=* sourcetype=aws:cloudtrail eventName=CreateUser
| eval newUser=spath(_raw,"requestParameters.userName")
| eval creator=spath(_raw,"userIdentity.userName")
| table _time, creator, newUser, sourceIPAddress, awsRegion`},
 {id:"CreateAccessKey",title:"Access key created",cat:"iam",risk:"high",desc:"Programmatic key created — persistent API access setup",
  mitre:["T1098","T1078"],
  setup:"CloudTrail management events (IAM global service).",
  fields:[["requestParameters.userName","Key target — creating for ANOTHER user is suspicious"],["userIdentity.userName","Creator"],["responseElements.accessKey.accessKeyId","Track this key immediately"],["sourceIPAddress","API call origin"]],
  corr:[["CreateUser","Key created right after new user provisioned?"],["AssumeRole","Does the key start making privileged calls?"]],
  iocs:[["r","Key created for another user — impersonation setup"],["r","Created right after compromise indicators"],["a","Outside business hours or unusual IP"],["g","Known pipeline rotating service keys"]],
  benign:["CI/CD key rotation","Admin provisioning new deployment"],
  query:`index=* sourcetype=aws:cloudtrail eventName=CreateAccessKey
| eval creator=spath(_raw,"userIdentity.userName")
| eval target=spath(_raw,"requestParameters.userName")
| where creator != target
| table _time, creator, target, sourceIPAddress`},
 {id:"AttachRolePolicy",title:"Policy attached to role",cat:"iam",risk:"high",desc:"IAM policy attached to a role — privilege escalation vector",
  mitre:["T1098","T1548"],
  setup:"CloudTrail management events (IAM global service).",
  fields:[["requestParameters.roleName","Role receiving the policy"],["requestParameters.policyArn","AdministratorAccess is critical"],["userIdentity.arn","Identity making the change"],["sourceIPAddress","Source of the call"]],
  corr:[["AssumeRole","Newly privileged role immediately assumed?"],["CreateUser","User created to use this role?"]],
  iocs:[["r","AdministratorAccess / * attached outside change window"],["r","Attached to a rarely-used or service role"],["a","From unexpected source IP"],["g","Known IaC pipeline attaching documented policies"]],
  benign:["Terraform/CDK deploying predefined roles"],
  query:`index=* sourcetype=aws:cloudtrail eventName=AttachRolePolicy
| eval role=spath(_raw,"requestParameters.roleName")
| eval policy=spath(_raw,"requestParameters.policyArn")
| where match(policy,"(?i)AdministratorAccess|PowerUser|FullAccess")
| table _time, role, policy, sourceIPAddress`},
 {id:"StopLogging",title:"CloudTrail stopped",cat:"defense",risk:"high",desc:"CloudTrail logging disabled — blinding before privileged actions",
  mitre:["T1562.008","T1562","T1070"],
  setup:"CloudTrail management events. Also enable a CloudWatch metric alarm on StopLogging as a backstop.",
  fields:[["requestParameters.name","Trail that was stopped"],["userIdentity.arn","Identity that disabled logging"],["sourceIPAddress","Call origin"],["userAgent","CLI disable more suspicious than console"]],
  corr:[["AssumeRole","What identity chain led to this?"],["CreateUser","IAM changes right after logging stopped?"]],
  iocs:[["r","Any StopLogging outside approved change windows"],["r","Immediately followed by privileged IAM/compute calls"],["a","Unusual IP or user agent"],["g","Documented maintenance with pre-approved change"]],
  benign:["Pre-approved infrastructure change window"],
  query:`index=* sourcetype=aws:cloudtrail eventName IN ("StopLogging","DeleteTrail","PutEventSelectors")
| eval trail=spath(_raw,"requestParameters.name")
| eval actor=spath(_raw,"userIdentity.arn")
| table _time, eventName, actor, trail, sourceIPAddress`},
 {id:"GetSecretValue",title:"Secret retrieved",cat:"credential",risk:"high",desc:"Secret pulled from Secrets Manager / SSM Parameter Store",
  mitre:["T1552","T1555","T1078"],
  setup:"Secrets Manager logs to CloudTrail by default. For SSM Parameter Store, ensure data events / GetParameter are captured.",
  fields:[["requestParameters.secretId","Which secret — DB creds, API keys"],["userIdentity.arn","Expected role vs unexpected identity"],["sourceIPAddress","Call origin"],["userAgent","CLI vs Lambda vs application SDK"]],
  corr:[["AssumeRole","Role assumption enabled the access?"],["ConsoleLogin","Done interactively through the console?"]],
  iocs:[["r","Secret accessed by identity not associated with it"],["r","External IP or unusual region"],["r","Many secrets pulled in sequence — dumping"],["a","Outside business hours or deployment windows"],["g","Application role accessing its own documented secrets"]],
  benign:["App containers pulling creds at startup","Deployment pipelines reading config"],
  query:`index=* sourcetype=aws:cloudtrail eventName=GetSecretValue
| eval secret=spath(_raw,"requestParameters.secretId")
| eval caller=spath(_raw,"userIdentity.arn")
| stats count as pulls, dc(secret) as unique_secrets
    by caller, sourceIPAddress, _time span=10m
| where unique_secrets > 3
| sort - unique_secrets`},
 {id:"ListBuckets",title:"Cloud enumeration",cat:"discovery",risk:"med",desc:"Discovery API bursts — mapping the account (buckets, users, roles, instances)",
  mitre:["T1526","T1087","T1082"],
  setup:"S3 ListBuckets is a management event. Enumeration of EC2/IAM (DescribeInstances, ListUsers, ListRoles) is captured in standard CloudTrail management events.",
  fields:[["eventName","ListBuckets, ListUsers, ListRoles, DescribeInstances, GetCallerIdentity"],["userIdentity.arn","Identity doing the enumeration"],["sourceIPAddress","External or new IP raises priority"],["userAgent","aws-cli / boto3 sweeps are common tooling"]],
  corr:[["AssumeRole","Enumeration right after a role assumption?"],["GetObject","Enumeration followed by bulk download?"]],
  iocs:[["r","Many distinct Describe/List calls from one identity in minutes"],["r","GetCallerIdentity then broad enumeration — orientation after compromise"],["a","Enumeration from a new IP or region for that identity"],["g","Cloud security/inventory tooling on schedule"]],
  benign:["CSPM / inventory scanners","IaC planning (terraform plan)"],
  query:`index=* sourcetype=aws:cloudtrail
    eventName IN ("ListBuckets","ListUsers","ListRoles","DescribeInstances","GetCallerIdentity")
| eval caller=spath(_raw,"userIdentity.arn")
| stats dc(eventName) as unique_calls, count as total
    by caller, sourceIPAddress, _time span=15m
| where unique_calls >= 3
| sort - total`},
 {id:"GetObject",title:"Mass S3 download",cat:"collection",risk:"high",desc:"High-volume S3 object retrieval — collection & exfiltration",
  mitre:["T1530","T1048","T1005"],
  setup:"REQUIRES S3 data events enabled on the trail (per-bucket or all buckets) — these are NOT captured by default management events.",
  fields:[["requestParameters.bucketName","Which bucket — sensitive-data buckets are priority"],["requestParameters.key","Object key retrieved"],["userIdentity.arn","Is this identity's access to this bucket normal?"],["sourceIPAddress","External IP is a major exfil signal"]],
  corr:[["ListBuckets","Enumeration preceding the download?"],["AssumeRole","Role assumption granting the access?"]],
  iocs:[["r","Hundreds/thousands of GetObject in minutes — bulk pull (T1530)"],["r","Download to an external IP address (T1048)"],["r","Access to a sensitive bucket by an unusual identity"],["a","First-time bucket access for this identity"],["g","Application/backup roles reading their own buckets"]],
  benign:["Application workloads reading their own data","Backup/replication jobs"],
  query:`index=* sourcetype=aws:cloudtrail eventName=GetObject
| eval bucket=spath(_raw,"requestParameters.bucketName")
| eval caller=spath(_raw,"userIdentity.arn")
| stats count as objects, dc(bucket) as buckets
    by caller, sourceIPAddress, _time span=15m
| where objects > 200
| sort - objects`}
];
