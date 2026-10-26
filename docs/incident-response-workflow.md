# Investigation workflow

The workspace uses a guidance sequence:

**Detection → Triage → Investigation → Containment → Eradication → Recovery → Resolution**

This is not a required sequence. Adapt it to the incident, organizational procedures, and potential impact to people and systems.

1. Record the source and scope of the alert; distinguish a synthetic demonstration from imported input.
2. Set ownership, severity, status, affected assets, and known facts.
3. Record observations and response actions with timestamps and analyst attribution.
4. Register evidence metadata and hashes where available. A hash can help detect changed bytes but does not independently establish provenance or authenticity.
5. Record IOC source and confidence. Do not visit submitted URLs or execute submitted files automatically.
6. Document impact, containment, eradication, recovery, recommendations, and unresolved questions without inventing findings.
7. Generate and review a report before sharing it.

Never record passwords, authentication tokens, or unnecessary personal information in investigation notes.
