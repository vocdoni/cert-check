# certauth/profiles/testdata: SOURCES

Files here are byte-for-byte copies (`cp`) of research-bundle files. `TestTSLInventorySource`
(`../tsl_test.go`) recomputes the SHA-256 below; `TestAnchorsGrantedInTSL` reads the inventory to
check that every pinned anchor is a current, granted CA/QC service identity with the pinned SPKI.

The inventory is a source-grounded export of the Spanish Trusted List (`TSL20260924`, sequence 189,
issued 2026-09-24, next update 2027-03-21; source `https://tsl.digital.gob.es/TSL.xml`, retrieved
2026-10-30). It is test data only, never a production trust configuration.

| file | source | SHA-256 |
|---|---|---|
| spanish_tsl_inventory_2026-10-30.json | `/home/p4u/certificate_poc/docs/Vocdoni_CSP_Handoff/spanish_tsl_inventory_2026-10-30.json` | 647da585e4949b6e6a14d7190dc7dead70a60e60b46b051d7de7829a9175a8b8 |
