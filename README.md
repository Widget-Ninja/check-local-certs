# check-local-certs

Scripts for the October 2026 eMudhra/emSign intermediate certificate compromise. `jamf-emsign.sh` checks whether a Mac's command-line tools and language runtimes still trust the compromised certificates, and fixes what it safely can. The same script runs on a developer's Mac and as a Jamf policy.

| File | What it is |
| --- | --- |
| `jamf-emsign.sh` | The audit and remediation script (v3.1.0). Bash 3.2, no dependencies beyond macOS. |
| `tests/run-tests.sh` | Test suite for `jamf-emsign.sh`, with public certificate fixtures in `tests/fixtures/`. |
| `eMudhra Certificate Remediation: Developer Mac Guide.md` | Guide for developers: what happened, what each finding means and how to fix it by hand. |
| `emsign-check.sh` | The earlier developer-only script, kept for reference. Its guide is in `docs/emsign-check-guide.md`. |

## Run it on your Mac

Run it as yourself, not with `sudo`. It audits first, then offers fixes and asks before each one.

```bash
chmod +x jamf-emsign.sh
./jamf-emsign.sh                 # audit, then offer fixes (asks before each one)
./jamf-emsign.sh --audit-only    # report only, change nothing
./jamf-emsign.sh --deep          # also scan $HOME and /Applications for vendored CA files
```

| Option | Effect |
| --- | --- |
| `--audit-only` | Report only; never prompt or change anything |
| `--deep` | Also search `$HOME` and `/Applications` for bundled CA files (slower) |
| `--yes` | Approve the routine fixes without prompting: Node, Homebrew, Java root removal, pip, certifi, uv |
| `--allow-destructive` | With `--yes`, also uninstall old Node versions (otherwise that always needs an interactive answer) |
| `--verbose` | Debug detail for each check |
| `--no-color` | Plain output |
| `--ea` | Print one `<result>` line only, and exit 0 |
| `--help` | Print the full usage from the script header |

Java fixes back up `cacerts` as `cacerts.emsign-bak-<timestamp>` before any change. The run ends with a **SUMMARY** block: the status, then **Fix now** (each item with its fix), **Waiting on a vendor**, and **Review**.

| Status | Exit code | Meaning |
| --- | --- | --- |
| PROTECTED | 0 | Every inspected runtime rejects the compromised certificates |
| VENDOR_PENDING | 1 | Nothing left to fix; the rest waits on Apple or an IDE vendor |
| EXPOSED | 2 | Something still trusts the compromised certificates and has a fix |
| UNVERIFIED | 3 | Something could not be checked; see **Review** |

WARN lines are advisories and never change the status. For what each finding means and how to fix it by hand, see the Developer Mac Guide.

## Run it in Jamf

As a Jamf policy the script runs as root. It does a system pass, then one pass per local user (UID 501 and up, with a home folder), each run as that user with a clean environment. Root never executes a binary a user owns. In `remediate` mode only Java is changed unattended; Node, Homebrew, pip and uv need the developer, so they are reported as actions.

### 1. Add the script

In Jamf Pro, go to **Settings → Computer management → Scripts → New**, paste in `jamf-emsign.sh`, and label the parameters:

| Parameter | Label | Values | Default |
| --- | --- | --- | --- |
| $4 | Mode | `audit` or `remediate` | `audit` |
| $5 | Verbose logging | `1` or `0` | `1` |
| $6 | Fail policy if exposed | `yes` or `no` | `yes` |
| $7 | Run jamf recon afterwards | `yes` or `no` | `no` |
| $8 | Users to scan | `all` or `console` | `all` |

`remediate` removes the four roots Oracle distrusted on 24 October (emSign ECC Root CA - G3, emSign Root CA - G1, emSign Root CA - G2 and AAA Certificate Services) from each unpatched JDK's `cacerts`. It keeps a verified backup, edits a staged copy, verifies it and then swaps it in. JDKs bundled inside IntelliJ or Android Studio are never edited.

### 2. Add the extension attribute

Create a computer extension attribute (**Settings → Computer management → Extension attributes**, input type Script) with this script. It reads the status file the policy writes, so inventory updates do not rescan the Mac:

```bash
#!/bin/bash
f="/Library/Application Support/emsign-check/status.plist"
[ -f "$f" ] || { echo "<result>Not run</result>"; exit 0; }
r=$(/usr/libexec/PlistBuddy -c "Print :Result" "$f" 2>/dev/null)
d=$(/usr/libexec/PlistBuddy -c "Print :LastRun" "$f" 2>/dev/null)
echo "<result>$r ($d)</result>"
```

Build smart groups on results that start with `EXPOSED` and `UNVERIFIED`.

### 3. Test on one Mac first

The script takes the same code path under `sudo` as under Jamf. `$1`–`$3` stand in for Jamf's mount point, computer name and user:

```bash
sudo ./jamf-emsign.sh / "$(hostname)" "$USER" audit
sudo ./jamf-emsign.sh / "$(hostname)" "$USER" remediate 1 no no console
# or with flags:
sudo ./jamf-emsign.sh --mode=audit --verbose --users=console
```

### 4. Roll out

1. Scope a policy running the script with $4 = `audit`. Nothing is changed; each Mac's log and status file list what `remediate` would do.
2. Once the audit results look right, switch $4 to `remediate` to fix Java fleet-wide.
3. Re-run on a schedule: a JDK update installs a fresh `cacerts`, so the fix only sticks once each Mac has a fixed JDK (8u511-b33, 11.0.33.0.3, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3, or a vendor build with JDK-8395690).

### Outputs

- The policy log (stdout) and `/var/log/emsign-check.log` (rotated at 5 MB).
- `/Library/Application Support/emsign-check/status.plist`: result, last run, counts, users scanned, failures and actions.
- Exit code: 0 for PROTECTED or VENDOR_PENDING; 1 for EXPOSED or UNVERIFIED when $6 is `yes`; 2 for bad parameters or when the script could not run.

Limits: Jamf runs do not load shell profiles, so variables a developer exports there (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `JAVA_HOME`) are only seen when developers run the script themselves.

## Run the tests

```bash
tests/run-tests.sh                        # tests ./jamf-emsign.sh
tests/run-tests.sh path/to/jamf-emsign.sh # tests another copy
```

- **Needs** bash, `openssl` and `perl`. The Java cases use a real `keytool` from `JAVA_HOME` or `PATH` (any JDK 9+); without one they are reported as skipped.
- **Safe to run anywhere**: macOS or Linux, no root needed. The suite sources the script, which loads its functions without starting a pass. All test input is generated in a temporary directory that is deleted afterwards.
- **Output**: one line per case grouped by area (bundles, certificate directories, keytool, Java policy, cross-signed path, environment, Node, Go, Gradle, Python, exit contract, command line), then `RESULT: N passed, N failed, N skipped`. The exit code is 0 only when nothing failed.

The fixtures in `tests/fixtures/` are public root certificates only; `tests/fixtures/README.md` lists each one with its fingerprints and source.
