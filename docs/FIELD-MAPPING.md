# Field mapping: HELK to TechDetechtives

HELK's Logstash pipeline renamed Windows event fields to its own flat names. The platform stores events in ECS. Use this table when porting a HELK notebook or query.

In Spark SQL views created by `td.to_spark()`, dots become underscores and `@timestamp` becomes `timestamp`, so `process.parent.name` is queried as `process_parent_name`.

| HELK field | Platform field (ECS) | Notes |
| --- | --- | --- |
| `@timestamp` | `@timestamp` | |
| `event_id` | `event.code` | String on the platform (`'4624'`, `'1'`) |
| `host_name` | `host.name` | |
| `user_name` | `user.name` | |
| `src_ip_addr` | `source.ip` | |
| `dst_ip_addr` | `destination.ip` | |
| `dst_port` | `destination.port` | |
| `process_name` | `process.name` | |
| `process_path` | `process.executable` | |
| `process_command_line` | `process.command_line` | |
| `process_guid` | `process.entity_id` | |
| `process_id` | `process.pid` | |
| `process_parent_name` | `process.parent.name` | |
| `process_parent_path` | `process.parent.executable` | |
| `process_parent_command_line` | `process.parent.command_line` | |
| `process_parent_guid` | `process.parent.entity_id` | |
| `user_logon_id` (Security 4624) | `winlog.event_data.TargetLogonId` | |
| `user_logon_id` (Sysmon 1) | `winlog.event_data.LogonId` | Sysmon events only |
| `logon_type` | `winlog.event_data.LogonType` | String (`'3'`) |
| `action == "processcreate"` | `event.category: process` and `event.type: start` | |

## Index patterns

| HELK index | Platform data stream | `td_hunt` data set |
| --- | --- | --- |
| `logs-endpoint-winevent-sysmon-*` | `logs-windows.sysmon_operational-*` | `process` |
| (none) | `logs-endpoint.events.process-*` (Elastic Defend) | `process` |
| `logs-endpoint-winevent-security-*` | `logs-system.security-*` | `logon` |
| `logs-network-zeek-*` | `logs-zeek-so*` | `zeek_conn` |
| (none) | `logs-suricata.alerts-*` | `alerts` |

Check field names against your own data before relying on a query: which fields are populated depends on the agent integrations you enable. Notebook 03 needs Sysmon process events, because Elastic Defend process events do not carry `winlog.event_data.LogonId`.
