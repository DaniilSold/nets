# Схемы данных

## JSON Schema — FlowEvent
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "FlowEvent",
  "type": "object",
  "required": [
    "ts_first", "ts_last", "proto", "src_ip", "src_port",
    "dst_ip", "dst_port", "direction", "bytes", "packets"
  ],
  "properties": {
    "ts_first": { "type": "string", "format": "date-time" },
    "ts_last": { "type": "string", "format": "date-time" },
    "proto": { "type": "string" },
    "src_ip": { "type": "string" },
    "src_port": { "type": "integer", "minimum": 0, "maximum": 65535 },
    "dst_ip": { "type": "string" },
    "dst_port": { "type": "integer", "minimum": 0, "maximum": 65535 },
    "iface": { "type": ["string", "null"] },
    "direction": { "type": "string", "enum": ["Inbound", "Outbound", "Lateral"] },
    "state": { "type": ["string", "null"] },
    "bytes": { "type": "integer", "minimum": 0 },
    "packets": { "type": "integer", "minimum": 0 },
    "process": {
      "type": ["object", "null"],
      "properties": {
        "pid": { "type": "integer" },
        "ppid": { "type": ["integer", "null"] },
        "name": { "type": ["string", "null"] },
        "exe_path": { "type": ["string", "null"] },
        "sha256_16": { "type": ["string", "null"] },
        "user": { "type": ["string", "null"] },
        "signed": { "type": ["boolean", "null"] }
      }
    },
    "layer2": {
      "type": ["object", "null"],
      "properties": {
        "kind": { "type": "string", "enum": ["Arp", "Nd"] },
        "operation": { "type": "string" },
        "mac_src": { "type": ["string", "null"] },
        "ip_src": { "type": ["string", "null"] },
        "mac_dst": { "type": ["string", "null"] },
        "ip_dst": { "type": ["string", "null"] }
      }
    },
    "sni": { "type": ["string", "null"] },
    "alpn": { "type": ["string", "null"] },
    "ja3": { "type": ["string", "null"] },
    "dns_qname": { "type": ["string", "null"] },
    "dns_qtype": { "type": ["string", "null"] },
    "dns_rcode": { "type": ["string", "null"] }
  }
}
```

## JSON Schema — Alert
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Alert",
  "type": "object",
  "required": ["id", "ts", "severity", "rule_id", "summary", "rationale"],
  "properties": {
    "id": { "type": "string" },
    "ts": { "type": "string", "format": "date-time" },
    "severity": { "type": "string", "enum": ["Low", "Medium", "High"] },
    "rule_id": { "type": "string" },
    "summary": { "type": "string" },
    "flow_refs": {
      "type": "array",
      "items": { "type": "string" }
    },
    "process_ref": { "type": ["string", "null"] },
    "rationale": { "type": "string" },
    "suggested_action": { "type": ["string", "null"] }
  }
}
```

## Protobuf контракты
```proto
syntax = "proto3";
package nets;

message ProcessIdentity {
  int32 pid = 1;
  int32 ppid = 2;
  string name = 3;
  string exe_path = 4;
  string sha256_16 = 5;
  string user = 6;
  bool signed = 7;
}

enum FlowDirection {
  INBOUND = 0;
  OUTBOUND = 1;
  LATERAL = 2;
}

enum Layer2EventKind {
  ARP = 0;
  ND = 1;
}

message Layer2EventMetadata {
  Layer2EventKind kind = 1;
  string operation = 2;
  string mac_src = 3;
  string ip_src = 4;
  string mac_dst = 5;
  string ip_dst = 6;
}

message FlowEvent {
  string ts_first = 1;
  string ts_last = 2;
  string proto = 3;
  string src_ip = 4;
  uint32 src_port = 5;
  string dst_ip = 6;
  uint32 dst_port = 7;
  string iface = 8;
  FlowDirection direction = 9;
  string state = 10;
  uint64 bytes = 11;
  uint64 packets = 12;
  ProcessIdentity process = 13;
  Layer2EventMetadata layer2 = 14;
  string sni = 15;
  string alpn = 16;
  string ja3 = 17;
  string dns_qname = 18;
  string dns_qtype = 19;
  string dns_rcode = 20;
}

enum Severity {
  LOW = 0;
  MEDIUM = 1;
  HIGH = 2;
}

message Alert {
  string id = 1;
  string ts = 2;
  Severity severity = 3;
  string rule_id = 4;
  string summary = 5;
  repeated string flow_refs = 6;
  string process_ref = 7;
  string rationale = 8;
  string suggested_action = 9;
}

service Netsd {
  rpc SubscribeFlows(stream FlowEvent) returns (stream FlowEvent);
  rpc GetAlerts(google.protobuf.Empty) returns (stream Alert);
  rpc ApplyQuarantine(QuarantineRequest) returns (QuarantineResponse);
  rpc ImportRules(RuleBundle) returns (ImportAck);
}
```
