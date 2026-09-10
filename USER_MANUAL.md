# Forensic Data Guard 4 — User Manual

## Start and sign in
Run `run_windows.bat`. On first use, create the Administrator. Passwords require at least eight characters, one letter, and one number. New accounts remain pending until an Administrator assigns Investigator or Auditor.

## Secure Drive Eraser
1. Run the application as Windows Administrator.
2. Open **Drive Eraser** and select **Refresh Devices**.
3. Carefully verify disk number, model, serial number, bus, capacity, and System status.
4. Select only the intended removable USB/SD/MMC device.
5. Select **Erase Selected Removable Drive** and type the exact displayed phrase.
6. Wait for completion. Do not unplug the device.

The Windows boot/system disk is blocked. The current implementation performs a full-device zero overwrite through Windows DiskPart. SSD wear levelling can prevent software overwrite from reaching remapped cells; use manufacturer-supported cryptographic erase or sanitize procedures when policy requires Purge-level sanitization.

## Secure File & Folder Eraser
1. Open **File Eraser**.
2. Add one or more files or folders.
3. Choose NIST Clear, Zero pass, Random pass, or Three pass.
4. Select **Erase Selected Targets** and type `ERASE SELECTED`.
5. Review the operation in **Operations**, **Audit Trail**, and **Reports**.

This operation is irreversible. Application data, roots, Windows, and protected system locations are blocked. File-level overwrite cannot guarantee removal from SSD remapped cells, snapshots, backups, or remote copies.

## File Carving & Recovery
1. Create a forensic image using an approved acquisition process.
2. Open **Recovery**.
3. Choose the read-only `.img`, `.dd`, `.raw`, `.bin`, or `.iso` source.
4. Choose a separate output folder, preferably on another drive.
5. Start recovery.
6. Review recovered outputs and the generated manifest.

The carver recognizes JPEG, PNG, PDF, ZIP-based containers, and GIF through headers and end markers. It records source offsets, SHA-256, structural validation, and confidence scores. The source file is opened read-only and checked for changes during processing.

## Reports and audit
Use **Reports** for case and operation reports. **Audit Trail** records user ID, username, action, target, outcome, and timestamp. **Settings** shows database integrity and audit-chain verification.

## Backup
Open **Settings**, choose **Back Up Database**, and save the backup on protected storage. Test restoration procedures according to organizational policy.
