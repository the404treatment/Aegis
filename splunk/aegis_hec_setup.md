# Splunk HEC setup for AEGIS

## Why this exists

AEGIS forwards every agent event to your Splunk instance so Splunk stays the
system of record. AEGIS keeps only a rolling window for the live UI.

**This does not replace a Universal Forwarder.** The agent ships a curated,
detection-relevant subset of Event IDs (see `$EventFilter` in `aegis-agent.ps1`).
For full-volume Windows log collection, run a Splunk UF alongside it — see
"Running both" below.

## 1. Create the index

Settings → Indexes → New Index → name `aegis`.

## 2. Create the HEC token

Settings → Data Inputs → HTTP Event Collector → New Token

- Name: `aegis`
- Source type: `aegis:agent`
- Index: `aegis`

Then Global Settings → All Tokens **Enabled**. Note the port (default 8088).

## 3. Point AEGIS at it

In `server/config.json`:

```json
"splunk": {
  "enabled": true,
  "url": "https://splunk.internal:8088/services/collector/event",
  "token": "PASTE-HEC-TOKEN",
  "index": "aegis",
  "sourcetype": "aegis:agent",
  "verifyTls": true
}
```

Set `verifyTls: false` **only** for a lab instance with a self-signed cert.
Restart the server. Events flush in batches of up to 500 every 1.5s.

## 4. Verify

```spl
index=aegis sourcetype=aegis:agent | head 20
```

If nothing arrives, check the AEGIS server log for `[splunk] HEC <code>`:
`403` means a bad token, `400` usually means the index does not exist.

## Field layout

Agents send a flat envelope with a nested `fields` object holding the
Windows event data that was actually present:

| Field | Meaning |
|---|---|
| `host` | reporting hostname |
| `channel` | `Security`, `Microsoft-Windows-Sysmon/Operational`, `System`, `syslog` |
| `eventId` | Windows Event ID, or a named pattern on Linux |
| `severity` | `info` / `suspicious` / `malicious`, set by the agent |
| `fields.CommandLine`, `fields.NewProcessName`, `fields.ParentImage`, `fields.TargetUserName`, `fields.IpAddress`, `fields.LogonType`, `fields.ServiceName`, `fields.ImagePath`, `fields.ObjectName` | when present in the source event |

## Starting searches

Encoded PowerShell, rare across the fleet:

```spl
index=aegis sourcetype=aegis:agent eventId=4688
| search fields.CommandLine="*-enc*" OR fields.CommandLine="*FromBase64String*"
| stats count dc(host) as hosts values(host) as seen_on by fields.CommandLine
| where hosts < 3
```

Service installs, suppressed against a known-good lookup:

```spl
index=aegis sourcetype=aegis:agent eventId=7045
| search NOT [| inputlookup aegis_known_services.csv | fields ImagePath]
| stats count dc(host) as hosts values(host) as seen_on by fields.ImagePath
| sort - count
```

**Silence detection** — an agent that stops reporting is itself a signal
(T1562 / T1211). Worth building first:

```spl
index=aegis sourcetype=aegis:agent
| stats latest(_time) as last by host
| eval mins=round((now()-last)/60,1)
| where mins > 15
| sort - mins
```

Risk roll-up per host:

```spl
index=aegis sourcetype=aegis:agent
| stats count(eval(severity="malicious")) as mal
        count(eval(severity="suspicious")) as sus
        dc(eventId) as distinct_ids by host
| eval risk=(mal*10)+(sus*3)
| where risk > 10 | sort - risk
```

Build the suppression lookup as you tune:

```spl
index=aegis sourcetype=aegis:agent eventId=7045
| stats count by fields.ImagePath
| where count > 20
| rename fields.ImagePath as ImagePath | fields ImagePath
| outputlookup aegis_known_services.csv
```

## Running both AEGIS and a Universal Forwarder

They complement each other and do not conflict — different transports,
different destinations. Recommended split:

- **UF** → full Security/Sysmon channels into your main Windows index, for
  retention, correlation, and the SPL that AEGIS generates in Detection Studio.
- **AEGIS agent** → the curated subset into `aegis`, for the live map,
  observations, and ticket context.

If you would rather have one pipeline, run only the UF and set
`splunk.enabled: false` — you lose live map population but keep everything else.
