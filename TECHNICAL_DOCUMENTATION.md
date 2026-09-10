# Technical Documentation

## Architecture
- `main.py`: Tkinter presentation layer and background-job coordinator
- `services.py`: authentication, case/evidence, and report business logic
- `sanitization.py`: guarded file/folder and removable-drive sanitization
- `recovery.py`: read-only signature/structure carving
- `database.py`: SQLite schema, transactions, audit hash chain
- `security.py`: validation, identifiers, scrypt password hashing
- `config.py`: local paths and security settings

## Data integrity
SQLite foreign keys, uniqueness constraints, explicit commit/rollback, operation records, SHA-256 evidence hashes, recovered-file hashes, source-image hash, and a SHA-256 chained audit seal are used. A hash chain is tamper-evident, not equivalent to an externally signed WORM log; export and retain reports on controlled storage for stronger assurance.

## Sanitization model
File/folder sanitization uses direct binary overwrite, flush/fsync, zero-sample verification when applicable, random filename replacement, deletion, and existence verification. Full removable-drive erasure invokes `diskpart clean all` with argument-list process execution. Boot/system disks are blocked; only USB, SD, and MMC devices are accepted; Administrator elevation and disk serial revalidation are required.

## Recovery model
The source is opened read-only and memory-mapped. The engine identifies file headers and bounded terminators, extracts contiguous candidates, validates structural markers, assigns confidence, hashes output, and writes a manifest. This release does not claim general reconstruction of arbitrarily fragmented files or repair of every damaged structure.

## Standards position
The implementation is designed with NIST SP 800-88-style Clear concepts, evidential integrity, chain-of-custody logging, and least-privilege controls in mind. Formal compliance depends on the selected media, approved organizational procedure, hardware behavior, validation evidence, tool qualification, operator training, and jurisdiction. The software does not self-certify legal or regulatory compliance.
