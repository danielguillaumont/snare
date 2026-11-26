# Detection content

Ready-made rules for Snare's OCSF 1.3 Detection Findings, one set per supported SIEM. Each
set has the same two detections:

| Detection | Severity | Logic |
|---|---|---|
| **Tripwire touched** | High | Any Snare finding with severity High or above. The sink test alert is Informational, so testing a sink never pages anyone. |
| **Several tripwires touched by one source** | Critical | Two or more distinct tripwires (`unmapped.token_id`) from one source IP in one tenant within an hour. The Splunk, Sentinel and Elastic rules compute this from raw findings. The Sigma rule keys on Snare's own correlation (`unmapped.correlated_tripwires >= 2`, see [M4c](../docs/M4c-reliability.md)). |

| SIEM | Files | Install |
|---|---|---|
| Splunk | [splunk/savedsearches.conf](splunk/savedsearches.conf) | Copy into an app's `local/savedsearches.conf`. Findings arrive with sourcetype `snare:ocsf:detection_finding`; add `index=` if you route them to a dedicated index. |
| Microsoft Sentinel | [sentinel/](sentinel/) | Import as scheduled analytics rules. They read the `SnareAlerts_CL` table written by the `sentinel` sink (columns below). |
| Elastic | [elastic/index-template.json](elastic/index-template.json), [elastic/snare-rules.ndjson](elastic/snare-rules.ndjson) | `PUT _index_template/snare-alerts` with the template **before** the first alert, so ids are `keyword` and `src_endpoint.ip` is `ip`. Then import the rules under Security → Rules → Import. |
| Sigma | [sigma/](sigma/) | Convert with your backend, using `logsource: product: snare, category: detection_finding` mapped to wherever findings land. |

**Sentinel table columns** (`SnareAlerts_CL`, set by the DCR stream declaration):

- `TimeGenerated` (datetime)
- `FindingUid`, `Title`, `Severity`, `SrcIp`, `Channel`, `TokenKind`, `TokenLabel` (string)
- `CorrelatedTripwires` (int)
- `Ocsf` (dynamic, the full finding)

## These rules are tested

`internal/alert/detections_test.go`:

1. Reads every file here and extracts each field path it uses.
2. Checks those paths against a real, correlated alert built by Snare's own code, in the
   shape each SIEM receives it:
   - the finding itself for Splunk and Sigma;
   - the finding plus `@timestamp` for Elastic;
   - `SentinelRecord` for Sentinel.
3. Checks that every Sentinel identifier is a real column or an alias the query defines.
4. Checks that the Elastic template maps only fields that exist.
5. Checks that every rule excludes the test alert.

If a field is renamed in `internal/alert`, CI fails. Each check was confirmed by breaking one
field per file.

**What is not tested:** the rules have not been run inside Splunk, Sentinel or Elastic. The
syntax was written against each product's documented format, not executed there. If you
import them and hit a problem, open an issue.

## Triage

A touch means something used a credential, link or tool that only exists as a trap.

1. **Who.** `src_endpoint.ip` and `unmapped.channel`.
   - For `http`, the IP is the client.
   - For `dns`, it is the client's resolver, so look upstream.
   - `unmapped.label` says where the tripwire was planted, and therefore which agent or data
     source could have reached it.
2. **Why.** Find the input the agent processed just before the touch: the email, ticket,
   page or document. A canary instruction's tag names the document it was planted in.
3. **Scope.**
   - Correlated alerts list the other touches in `finding_info.related_events`.
   - Assume anything the agent's real credentials could reach was reachable for the attacker.
   - Rotate those credentials, not the honey ones.
4. **False positive?** Only if a person was testing. Snare's measured benign trip rate is
   0/600 normal agent runs ([results](../docs/results-m0.md)).
