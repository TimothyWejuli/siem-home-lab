# Saved Detection Queries (Wazuh DQL)

Use in **Threat intelligence > Threat Hunting > Events**. Remove any `rule.level` filter first, and set an appropriate time range.

| Purpose | Query |
|---|---|
| Detection Test 1 – all account events | `data.win.system.eventID: (4625 or 4720 or 4732 or 4726)` |
| Failed logons | `data.win.system.eventID: 4625` |
| New local accounts | `data.win.system.eventID: 4720` |
| Admin group changes (high severity) | `rule.id: 60154` |
| Accounts deleted | `data.win.system.eventID: 4726` |
| High and critical alerts only | `rule.level >= 12` |
| Everything from one agent | `agent.name: "BBC"` |
| Alerts tagged with a MITRE technique | `rule.mitre.id: "T1098"` |

## Windows Event ID reference

| Event ID | Meaning | MITRE ATT&CK |
|---|---|---|
| 4624 | Successful logon | T1078 – Valid Accounts |
| 4625 | Failed logon | T1110 – Brute Force |
| 4672 | Special privileges assigned at logon | T1078 |
| 4720 | User account created | T1136.001 – Create Account: Local Account |
| 4732 | Member added to security-enabled local group | T1098 – Account Manipulation |
| 4726 | User account deleted | T1531 – Account Access Removal |

## Wazuh severity bands (dashboard)

| Band | Rule level |
|---|---|
| Low | 0–6 |
| Medium | 7–11 |
| High | 12–14 |
| Critical | 15+ |
