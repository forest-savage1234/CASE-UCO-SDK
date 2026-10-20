# ICS/SCADA and OT Network Intrusion Modeling

> See [Recipe Index](INDEX.md) for all recipes.

Model industrial control system (ICS) and supervisory control and data
acquisition (SCADA) intrusion investigations — PLC/HMI assets, OT VLAN packet
captures, Modbus/TCP (or similar) process writes, historian alarm exports, and
engineering-workstation project files — using core CASE/UCO types, plus
[MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/) technique types
on the adversary actions the evidence shows.

**Validated against** `examples/otics/otics-scada-intrusion.jsonld` (Tier T0
synthetic Operation COOLING TOWER; DFRWS Rodeo team **Victims First!**).

## When to use this recipe

- Submitted content mentions PLC, RTU, HMI, SCADA, DCS, historian, Modbus,
  DNP3, EtherNet/IP, OPC UA, setpoints, ladder logic, or OT/ICS segmentation
- `route_investigation_content` returns a weak network/intrusion match but the
  evidence is process-control oriented rather than enterprise IT
- Neighboring recipes: [network-investigation.md](network-investigation.md) for
  general PCAP workflows; [cyber-threat-intelligence.md](cyber-threat-intelligence.md)
  for ATT&CK narrative; [spear-phishing.md](spear-phishing.md) when the initial
  access vector is email

## Scope

| Layer | What it captures | Primary classes |
|---|---|---|
| **Acquisition** | OT SPAN/pcap, tool, examiner | `InvestigativeAction`, `Tool`, `FileFacet`, `ContentDataFacet`, `ProvenanceRecord` |
| **OT assets** | PLC, HMI/SCADA server, engineering workstation | `EmbeddedDevice`, `NetworkAppliance`, `Device` + `DeviceFacet` |
| **Process traffic** | Industrial protocol sessions (e.g. Modbus/TCP :502) | `TCPConnection`, `NetworkConnectionFacet`, `NetworkFlowFacet`, `IPAddress` |
| **Process events** | Historian alarms, HMI audit / logic-download rows | `EventRecord`, `EventRecordFacet` |
| **Analysis** | Correlation of writes ↔ alarms ↔ project files | Separate `InvestigativeAction` + `AnalyticTool` |
| **Adversary behavior** | Evidenced intrusion steps (program download, parameter change) | `Action` typed with an ATT&CK for ICS technique |
| **Case** | Investigation container | `Investigation` |

## Key classes

| Class | Role |
|---|---|
| `Investigation` | Case container (create last) |
| `InvestigativeAction` | Capture action and separate analysis action |
| `EmbeddedDevice` | PLC / RTU / dedicated controllers |
| `NetworkAppliance` | HMI / SCADA servers and similar supervisory hosts |
| `Device` + `DeviceFacet` | Engineering workstations; `deviceType` carries free-text role labels |
| `EventRecord` + `EventRecordFacet` | Historian alarms and HMI audit events |
| `TCPConnection` + network facets | Industrial protocol sessions observed in PCAP |
| `Relationship` | `Contained_Within`, `Connected_To` (directional) |
| `ProvenanceRecord` | Links acquired exhibits to the acquisition action |
| `Action` | An adversary step the evidence shows; also typed with its ATT&CK for ICS technique |

## Pattern

```
Investigation
  ├── InvestigativeAction (OT SPAN capture)
  │     ├── uco-action:instrument ──▶ Tool (Wireshark)
  │     ├── uco-action:object ──▶ HMI / PLC / ENG-WS
  │     └── uco-action:result ──▶ File (pcapng)
  ├── InvestigativeAction (Modbus ↔ historian analysis)
  │     ├── uco-action:instrument ──▶ AnalyticTool
  │     ├── uco-action:object ──▶ pcap, CSV, project file, connections, events
  │     ├── uco-action:result ──▶ Modbus write, HIHI alarm, adversary Actions
  │     └── case-investigation:wasInformedBy ──▶ capture action
  ├── Action, also typed ATT&CK T0843 (Program Download)
  │     ├── uco-action:object ──▶ PLC
  │     └── uco-action:instrument ──▶ ENG-WS, PLC project file
  ├── Action, also typed ATT&CK T0836 (Modify Parameter)
  │     ├── uco-action:object ──▶ PLC
  │     └── uco-action:instrument ──▶ TCPConnection (Modbus/TCP writes)
  ├── EmbeddedDevice (PLC) ──Connected_To──▶ IPAddress
  ├── NetworkAppliance (HMI) ──Connected_To──▶ IPAddress
  ├── Device (ENG-WS) ──Connected_To──▶ IPAddress
  ├── TCPConnection (Modbus/TCP) ──Contained_Within──▶ pcap
  └── EventRecord (HIHI / PROGRAM_DOWNLOAD) ──Contained_Within──▶ CSV
```

<details open><summary>Python</summary>

```python
from case_uco import CASEGraph
from case_uco.uco.observable import (
    EmbeddedDevice, NetworkAppliance, Device, DeviceFacet,
    TCPConnection, NetworkConnectionFacet, NetworkFlowFacet,
    EventRecord, EventRecordFacet, IPAddress, IPAddressFacet,
)
from case_uco.uco.identity import Organization

graph = CASEGraph(kb_prefix="http://example.org/kb/")
vendor = graph.create(Organization, name="PLC Vendor (synthetic)")

plc = graph.create(
    EmbeddedDevice,
    name="PLC-RAW-03",
    has_facet=[DeviceFacet(
        device_type="programmable-logic-controller",
        manufacturer=vendor,
        model="ControlLogix 1756-L83E (synthetic)",
        serial_number="SN-T0-PLC-RAW-03",
    )],
)
hmi = graph.create(
    NetworkAppliance,
    name="HMI-CLEARSCADA-01",
    has_facet=[DeviceFacet(device_type="scada-hmi-server")],
)
# Full end-to-end builder:
#   python examples/otics/build_otics_scada_intrusion.py
```

The builder adds every inline facet and `Hash` with `graph.add(..., id=...)`
before attaching it, so each rebuild produces the same IRIs.

</details>

## Adversary techniques (ATT&CK for ICS)

The SDK ships the full MITRE ATT&CK catalog, including the ICS domain, as the
`attack-technique` extension. Each technique is a class under
`uco-action:Technique`, so an adversary `Action` takes the technique as a
second `rdf:type`:

```python
from case_uco.uco.action import Action

modify_parameter = graph.create(
    Action,
    name="Raise pump discharge pressure setpoint on PLC-RAW-03",
    object=[plc],
    instrument=[modbus_write],  # the TCPConnection that carried the writes
)
graph.add_type(graph.get_id(modify_parameter),
               "https://attack.mitre.org/techniques/T0836")
```

**Type only what the evidence shows.** A technique type is a claim that an
artifact in the graph shows that tradecraft; keep the artifact on the action as
its `object` or `instrument`. In the exemplar:

| Evidence | Technique |
|---|---|
| HMI audit row `AUD-2026-0314-221`: project downloaded to PLC-RAW-03 from ENG-WS-07 outside the change window | [T0843 Program Download](https://attack.mitre.org/techniques/T0843) |
| Modbus/TCP function code 16 writes from ENG-WS-07 to PLC-RAW-03, followed by the HIHI alarm | [T0836 Modify Parameter](https://attack.mitre.org/techniques/T0836) |

The exemplar has no remote-access logs, so it does not claim
[T0886 Remote Services](https://attack.mitre.org/techniques/T0886) even though
it is a common initial-access path in OT intrusions. Leave `performer` off:
the `ENGTEC` account in the audit row names a credential, not who used it. Find
techniques with the `search_adversary_techniques` and
`get_adversary_technique` MCP tools.

## Anti-patterns

- **Do not invent ICS ontology terms** (`otics:PLC`, `modbus:functionCode`, …) in
  graphs meant for public CASE/UCO validation. Capture vendor/protocol detail in
  `description` / `eventRecordText` until a proposal lands, or declare a local
  extension per [extensions.md](extensions.md).
- **Do not collapse acquisition and analysis** into one `InvestigativeAction`.
  Keep PCAP facts separate from setpoint-change inferences.
- **Do not type a PLC as `SmartDevice`** solely because it is networked — prefer
  `EmbeddedDevice` (purpose-built controller) or `NetworkAppliance` (supervisory
  host). Record the OT role in `DeviceFacet.deviceType`.
- **Do not put process setpoints only in free-text** without also linking the
  `EventRecord` / `TCPConnection` nodes that justify the inference.
- **Do not use `EventRecordFacet(event_id=...)`.** The UCO property is
  `eventRecordID`, set with `event_record_id`; `event_id` maps to a term that
  doesn't exist.
- **Do not add an ATT&CK for ICS type by association** (for example, because
  OT intrusions usually involve remote services). Add one only for a step an
  artifact shows, and never type examiner actions with ATT&CK.

## Ontology gaps (self-improvement input)

While this recipe validates today, core UCO lacks typed properties for:

1. PLC firmware revision, rack/slot addressing, and controller program identity
2. Industrial protocol function codes / object addresses (Modbus, DNP3, CIP, …)
3. Process tag names, engineering units, and setpoint before/after values

See the companion change proposal
`change_proposals/industrial-control-device-facet.md` and file/ upstream against
[ucoProject/UCO](https://github.com/ucoProject/UCO/issues).

## Checklist

1. Create utility `Organization` and examiner `Identity`
2. Model PLC as `EmbeddedDevice`, HMI as `NetworkAppliance`, ENG-WS as `Device`
3. Attach `DeviceFacet` with OT role in `deviceType` and serial/model when known
4. Model IPs and `Connected_To` relationships (set `is_directional=True`)
5. Model industrial sessions as `TCPConnection` with ports (e.g. 502) and flows
6. Model historian/HMI rows as `EventRecord` + `EventRecordFacet`
7. Separate capture vs analysis `InvestigativeAction`s; add `ProvenanceRecord`
8. Add an adversary `Action` for each step the evidence shows, typed with its
   ATT&CK for ICS technique; no `performer` unless the evidence attributes it
9. Create `Investigation` last, linking actions and key observables
10. Validate with the ATT&CK catalog loaded (see below)

## Validated exemplar

| Artifact | Path |
|---|---|
| Scenario (Tier T0) | [examples/otics/operation-cooling-tower.md](../../examples/otics/operation-cooling-tower.md) |
| Builder | [examples/otics/build_otics_scada_intrusion.py](../../examples/otics/build_otics_scada_intrusion.py) |
| Graph | [examples/otics/otics-scada-intrusion.jsonld](../../examples/otics/otics-scada-intrusion.jsonld) |

```bash
python examples/otics/build_otics_scada_intrusion.py
case_validate --built-version case-1.5.0 --allow-info \
  --ontology-graph extensions/attack-technique/mitre-attack-catalog.ttl \
  examples/otics/otics-scada-intrusion.jsonld
```

## Validation queries

Run these against the exemplar to confirm the graph answers the
investigator's questions. Each returns at least one row.

Which Modbus/TCP sessions wrote to a controller, and when?

```sparql
PREFIX uco-core: <https://ontology.unifiedcyberontology.org/uco/core/>
PREFIX uco-observable: <https://ontology.unifiedcyberontology.org/uco/observable/>
SELECT ?connection ?dstAddress ?start ?end WHERE {
  ?connection a uco-observable:TCPConnection ;
      uco-core:hasFacet ?nc .
  ?nc a uco-observable:NetworkConnectionFacet ;
      uco-observable:destinationPort 502 ;
      uco-observable:dst/uco-core:hasFacet/uco-observable:addressValue ?dstAddress ;
      uco-observable:startTime ?start ;
      uco-observable:endTime ?end .
}
```

Which historian or HMI records were logged at or after the end of a write session?

```sparql
PREFIX uco-core: <https://ontology.unifiedcyberontology.org/uco/core/>
PREFIX uco-observable: <https://ontology.unifiedcyberontology.org/uco/observable/>
SELECT ?recordID ?alarmTime ?writeEnd WHERE {
  ?conn a uco-observable:TCPConnection ;
      uco-core:hasFacet/uco-observable:endTime ?writeEnd .
  ?event uco-core:hasFacet ?ef .
  ?ef a uco-observable:EventRecordFacet ;
      uco-observable:eventRecordID ?recordID ;
      uco-observable:startTime ?alarmTime .
  FILTER (?alarmTime >= ?writeEnd)
}
```

Which unattributed adversary actions carry an ATT&CK technique, and what did they target?

```sparql
PREFIX uco-core: <https://ontology.unifiedcyberontology.org/uco/core/>
PREFIX uco-action: <https://ontology.unifiedcyberontology.org/uco/action/>
SELECT ?action ?technique ?targetName ?start WHERE {
  ?action a uco-action:Action , ?technique ;
      uco-action:object/uco-core:name ?targetName ;
      uco-action:startTime ?start .
  FILTER STRSTARTS(STR(?technique), "https://attack.mitre.org/techniques/")
  FILTER NOT EXISTS { ?action uco-action:performer ?anyone }
}
ORDER BY ?start
```

## Related

- [sosa-sensor-observations.md](sosa-sensor-observations.md) — process-sensor and historian readings as observations with QUDT results
- [network-investigation.md](network-investigation.md) — PCAP three-layer pattern
- [cyber-threat-intelligence.md](cyber-threat-intelligence.md) — threat narrative and ATT&CK typing
- [cross-ontology-composition.md](cross-ontology-composition.md) — when to combine technique vocabularies (principle 6)
- [change-proposal.md](change-proposal.md) — upstreaming ICS facet gaps
- [recipe-authoring.md](recipe-authoring.md) — catalog registration rules
