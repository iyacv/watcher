# Class Diagram — Grafana-Based Security Log Visualization and Prioritization Dashboard

Aligned with the actual system: watchdog → parsers (F5 / Log360) → storage (Postgres/SQLite) → Grafana.

---

## Entity classes (data layer)

### Vulnerability
```
- id: bigint  [PK]
- host: string
- url: string
- name: string
- attack_type: string
- cookie: string
- severity: enum {critical, high, medium, low, info}
- cvss: float
- status: enum {open, resolved}
- detected_at: datetime
- last_seen: datetime
- raw_hash: string  [unique]
- aged: boolean
- source_file: string
- created_at: datetime
```

### Event
```
- id: bigint  [PK]
- host: string
- event_id: string
- event_type: string
- severity: enum {error, failure, warning, information, success}
- user: string
- display_name: string
- detected_at: datetime
- raw_hash: string  [unique]
- source_file: string
- created_at: datetime
```

### VulnerabilityChange
```
- id: bigint  [PK]
- vuln_hash: string  [FK → Vulnerability.raw_hash]
- host: string
- name: string
- old_severity: string
- new_severity: string
- changed_at: datetime
```

### Correlation
```
- id: bigint  [PK]
- host: string
- vuln_id: string   [FK → Vulnerability]
- event_id: string  [FK → Event]
- event_type: string
- vuln_time: datetime
- event_time: datetime
- severity: enum {critical, high, medium, low, info}
- created_at: datetime
```

---

## Service / processing classes

### Watchdog
```
- inbox_path: string
- poll_interval: int
+ start(): void
+ onFileCreated(path: string): void
+ stop(): void
```

### F5Parser
```
+ parse(file: string): List<Vulnerability>
+ validate(record: dict): boolean
```

### Log360Parser
```
+ parse(file: string): List<Event>
+ validate(record: dict): boolean
```

### Analyzer
```
+ correlate(vuln: Vulnerability, event: Event): Correlation
+ detectAging(vuln: Vulnerability): boolean
+ detectSeverityChange(old: Vulnerability, new: Vulnerability): VulnerabilityChange
```

### StorageRepository
```
- connection: DBConnection
+ upsertVulnerability(v: Vulnerability): void
+ upsertEvent(e: Event): void
+ insertCorrelation(c: Correlation): void
+ insertChange(ch: VulnerabilityChange): void
+ queryBySeverity(level: string): List<Vulnerability>
+ queryByDateRange(start, end): List<Event>
```

### GrafanaDashboard  «external»
```
+ filterBySeverity(): void
+ showTopSeverity(): void
+ displayTrend(): void
+ queryDatasource(sql: string): ResultSet
```

---

## Relationships

| From | To | Type | Notes |
|---|---|---|---|
| Watchdog | F5Parser | uses | Routes F5 log files |
| Watchdog | Log360Parser | uses | Routes Log360 XML/JSON files |
| F5Parser | Vulnerability | creates | One file → many vulnerabilities |
| Log360Parser | Event | creates | One file → many events |
| Analyzer | Vulnerability | reads | For correlation + aging |
| Analyzer | Event | reads | For correlation |
| Analyzer | Correlation | creates | Composition (1..*) |
| Analyzer | VulnerabilityChange | creates | When severity changes |
| StorageRepository | Vulnerability | persists | CRUD |
| StorageRepository | Event | persists | CRUD |
| StorageRepository | Correlation | persists | CRUD |
| StorageRepository | VulnerabilityChange | persists | CRUD |
| GrafanaDashboard | StorageRepository | queries | Read-only via SQL datasource |
| Vulnerability | VulnerabilityChange | 1..* | History of severity changes |
| Vulnerability | Correlation | 1..* | A vuln can appear in many correlations |
| Event | Correlation | 1..* | An event can appear in many correlations |

---

## Layout suggestion for draw.io

```
┌─────────────────┐         ┌─────────────────┐
│    Watchdog     │────────►│    F5Parser     │──creates──►┌──────────────────┐
└────────┬────────┘         └─────────────────┘            │  Vulnerability   │
         │                                                 │  (entity)        │
         │                  ┌─────────────────┐            └────────┬─────────┘
         └─────────────────►│   Log360Parser  │──creates──►         │
                            └─────────────────┘                     │ 1..*
                                                                    ▼
                                                          ┌──────────────────────┐
                            ┌─────────────────┐           │ VulnerabilityChange  │
                            │    Analyzer     │──creates─►└──────────────────────┘
                            └────────┬────────┘
                                     │                    ┌──────────────────┐
                                     ├──reads───────────► │     Event        │
                                     │                    └────────┬─────────┘
                                     │                             │ 1..*
                                     │                             ▼
                                     └──creates──►┌──────────────────────────┐
                                                  │       Correlation         │
                                                  └──────────────────────────┘

         ┌────────────────────────┐
         │  StorageRepository     │◄── persists all entity classes
         └───────────┬────────────┘
                     │ queries
                     ▼
         ┌────────────────────────┐
         │  GrafanaDashboard      │   «external»
         │  - filterBySeverity()  │
         │  - showTopSeverity()   │
         │  - displayTrend()      │
         └────────────────────────┘
```

---

## Notes for defense panel

1. **Why no separate `scan_report` table?**
   Your watchdog ingests individual log files, not bundled scan reports. The `source_file` column on Vulnerability/Event preserves provenance without an extra join.

2. **Why `Vulnerability` AND `Event` instead of one log table?**
   F5 emits *vulnerability scan results* (with CVSS, attack type). Log360 emits *system/auth events* (with user, event_type). They have different shapes; merging them would force NULLs everywhere.

3. **Why is GrafanaDashboard marked `«external»`?**
   Grafana is third-party software queried via SQL datasource. It's not code your team writes — it's a consumer of `StorageRepository`.

4. **Why is `Trend` not a class?**
   Trends are *computed views* (Grafana queries over time windows), not stored entities. They're derived, not persisted — so they live in Grafana panels, not the schema.

5. **`raw_hash` purpose**
   Deduplication. Same log line ingested twice (e.g., file replayed) won't create duplicate rows — the UNIQUE constraint on `raw_hash` rejects it.
