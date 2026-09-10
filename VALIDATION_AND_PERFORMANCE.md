# Validation and Performance Guide

## Automated validation
Run `py -3 -m unittest discover -s tests -v`. Tests cover authentication, uniqueness, approval, account protection, evidence hashing, file erasure, operation records, signature recovery, classification, manifests, reporting, and audit-chain tamper detection.

## Required Windows acceptance tests
- Enumerate test USB/SD media without showing the system disk as erasable.
- Reject incorrect confirmation, changed serial number, nonremovable bus type, and non-elevated execution.
- Erase only disposable test media; verify every readable sector is zero using an independent tool.
- Test file/folder methods on NTFS, exFAT, and FAT32 disposable media.
- Verify protected paths and application data are rejected.
- Recover known test corpora from RAW/DD images and compare hashes.
- Test malformed, truncated, nested, duplicate-signature, and maximum-size candidates.
- Interrupt recovery and erasure in a controlled test; verify truthful failed status and usable restart.
- Validate generated reports and the audit hash chain.
- Test 1024×700, 1280×800, and high-DPI displays.

## Performance measurement
Record source size, storage type, connection, operation method, elapsed time, throughput, CPU, memory, recovered known files, false positives, valid hashes, and confidence. Do not publish recovery-rate claims without a documented representative corpus.

## Current algorithmic characteristics
- Hashing/overwrite: sequential I/O, approximately O(n), 1 MiB blocks.
- Carving: memory-mapped signature searches per supported type; output count capped at 500 per operation.
- Memory: mapped source plus one extracted candidate in memory; bounded candidate size by type.

## Independent verification
For production or evidentiary use, qualify the tool against recognized test images and independent sanitization verification utilities. Retain software version, test corpus hashes, device identifiers, configuration, and full results.
