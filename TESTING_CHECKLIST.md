# Complete Testing Checklist

## Authentication and authorization
- [x] Password hashing and verification
- [x] Minimum 8 characters with letter and number
- [x] Case-insensitive username uniqueness
- [x] Pending registration and Administrator approval
- [x] Account lockout and final Administrator protection
- [x] Role-aware navigation

## Evidence and cases
- [x] Case creation
- [x] Evidence registration and SHA-256
- [x] Unchanged-file verification
- [x] Modified-file mismatch detection
- [x] Missing-source handling

## File and folder sanitization
- [x] File overwrite, flush, verification, rename, and deletion
- [x] Operation and audit records
- [x] Empty-target rejection
- [ ] Windows test on disposable NTFS, exFAT, and FAT32 media
- [ ] Independent post-erasure sector inspection
- [ ] SSD/flash limitation warning review

## Secure drive erasure
- [x] Source-level system/boot-disk block
- [x] Source-level removable-bus restriction
- [x] Exact confirmation and serial revalidation
- [x] Administrator elevation requirement
- [ ] Disposable USB/SD full-device acceptance test on Windows
- [ ] Independent all-sector zero verification

## Recovery
- [x] Read-only source access
- [x] JPEG and PDF synthetic carving
- [x] Automatic classification
- [x] Structural validation and confidence
- [x] Recovered-file and source hashes
- [x] Manifest creation
- [ ] Known-corpus recovery-rate measurement
- [ ] Large-image and damaged-image Windows tests

## Reporting and audit
- [x] Case report
- [x] Operation report
- [x] HTML escaping
- [x] Audit hash chain verification
- [x] Tamper detection test

## UI/build acceptance
- [x] Python syntax compilation
- [x] Automated service tests
- [ ] Windows packaged-EXE smoke test
- [ ] 1024×700, 1280×800, and high-DPI visual review
- [ ] Long-operation cancellation/power-loss procedure test
