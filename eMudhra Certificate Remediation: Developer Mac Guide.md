# eMudhra Certificate Remediation: Developer Mac Guide

Oct 26, 2026 · @Lucas · for `jamf-emsign.sh` v3.1.0

## What happened

Every developer Mac needs its Node, Java and Python trust stores updated this week; browsers are already protected. On 17 October 2026 the private keys of eight eMudhra certificate authorities were found to be trivially weak. Anyone holding them can mint a certificate for any site that an unpatched tool will accept.

Safari, Chrome and Firefox blocked the certificates within days. Command-line tools and language runtimes carry their own copy of trusted roots and do not check revocation, so they still trust forged certificates until updated:

- **Node.js** (npm, Yarn): fixed releases shipped 21 October.
- **Java**: every JDK, including the ones bundled inside IntelliJ and Android Studio.
- **Python**: pip (its own built-in certificate list), certifi in each virtualenv, and Homebrew's CA bundle.
- **uv**, **Go** (1.26.10 / 1.27.3; rebuild binaries you ship) and any file-based CA bundle.

The compromised intermediates chain to **emSign ECC Root CA - G3** and, through Sectigo cross-signs, to **AAA Certificate Services**. The script recognizes these certificates by their public keys, not their names, so a renamed copy is still caught. The other emSign roots (G1, C1, ECC C3) are not affected.

Fix time: about 20–30 minutes per machine.

## 1. Run the script

Run `jamf-emsign.sh` as yourself (not with sudo): it audits first, then offers fixes and confirms each one, so most Macs need nothing else. Sections 2–4 are the manual steps behind each fix.

```bash
# Get jamf-emsign.sh from: <INTERNAL LOCATION – repo, wiki or Self Service>
chmod +x jamf-emsign.sh
./jamf-emsign.sh                 # audit, then offer fixes (asks before each one)
./jamf-emsign.sh --audit-only    # report only, change nothing
./jamf-emsign.sh --deep          # also scan virtualenvs and app-bundled CA files
./jamf-emsign.sh --help          # every option
```

- Answer **y** to "Proceed to remediation?", then y or n to each fix. Java's `cacerts` is backed up as `cacerts.emsign-bak-<timestamp>` before any change.
- `--yes` approves the routine fixes without prompting, including the Java root removal. Uninstalling old Node versions still needs your interactive answer (or `--yes --allow-destructive`).
- Run it from any folder; npm and Yarn are never started inside your projects, so a pinned package manager cannot stall it.

The run ends with a **SUMMARY** block: a STATUS line, then **Fix now** (each item with its fix), **Waiting on a vendor**, and **Review**.

| STATUS | Exit code | What it means for you |
| --- | --- | --- |
| PROTECTED | 0 | Done |
| VENDOR\_PENDING | 1 | Done for now; what is left waits on Apple or an IDE vendor |
| EXPOSED | 2 | Work through **Fix now** |
| UNVERIFIED | 3 | Something could not be checked; follow **Review**, or send the summary to \<CONTACT> |

WARN lines are advisories and never change the status. "Not covered" lists what the script cannot check; it is not counted.

## 2. Node.js, npm and Yarn

Upgrade every installed Node version to a fixed release, not just your default; npm and Yarn 1 run on the active Node, so they are fixed with it.

| Line | Minimum fixed version |
| --- | --- |
| 26.x | 26.12.1 |
| 24.x | 24.22.1 |
| 22.x | 22.23.4 |
| 20.x and older | No fix (end of life); move to 22 or 24 |

With nvm:

```bash
nvm ls                                    # see every installed version
nvm install 24 --reinstall-packages-from=current
nvm install 22                            # only if a project still needs 22
nvm alias default 24
nvm uninstall 24.16.0                     # repeat for each old version the audit flagged
node --version                            # confirm
```

With Homebrew: `brew upgrade node` (or `node@22`). With Volta: `volta install node@24`.

**If you set** `NODE_OPTIONS=--use-system-ca`: Node versions before 22.15 refuse to start with it, so remove those versions. The flag also pulls in macOS's roots, and Apple's revocation does not protect Node, so the upgrade is still required.

After upgrading, delete and reinstall `node_modules` only if a project pins an `engines` range the new version breaks; the fix itself needs no reinstall.

**Extra CA files:** a patched Node rejects the compromised certificates even if `NODE_EXTRA_CA_CERTS` adds AAA or emSign roots, so the script only notes that file once every Node on the Mac is patched. **Corepack:** if a project pins an older npm or Yarn (`"packageManager"` in `package.json`), Corepack asks before downloading it; run `npm` once inside that project and answer the prompt, or update the pin.

## 3. Java (JDK 21 and any other JDK)

Oracle changed its guidance on 24 October (CVE-2026-114820, JDK-8395690): the 21 October blocklist builds are now listed as affected. A JDK is fixed only when its `cacerts` no longer trusts the four roots Oracle removed: **emSign ECC Root CA - G3**, **emSign Root CA - G1**, **emSign Root CA - G2** and **AAA Certificate Services** (aliases `emsigneccrootcag3`, `emsignrootcag1`, `emsignrootcag2`, `comodoaaaca`). The script matches them by key, so a renamed copy is still found, and reports `blocked.certs` for context only.

Fix in this order:

1. **Install a fixed JDK** where your vendor has one: 8u511-b33, 11.0.33.0.3, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3 or 27.0.1.0.3, or a vendor build that includes JDK-8395690.
2. **Otherwise let the script remove the four roots**, which is what the fixed builds ship. Answer y to "Remove … distrusted root(s)". It keeps a verified backup (`cacerts.emsign-bak-<timestamp>`), edits a staged copy, verifies it and only then swaps it in. Only entries with those exact keys are removed; a same-named entry with another key goes to Review instead. Then restart running Java processes and Gradle daemons: `./gradlew --stop`.
3. **Optionally add revocation checking:** `-Dcom.sun.net.ssl.checkRevocation=true -Dcom.sun.security.enableCRLDP=true` in `JAVA_TOOL_OPTIONS`. Test it first; connections fail where CRL endpoints are unreachable.

A JDK update installs a fresh `cacerts` with the roots back in, so re-run the script after each one until you are on a fixed build.

To undo a removal, copy the backup back over `cacerts` (for example `cp -p cacerts.emsign-bak-<timestamp> cacerts` in that JDK's `lib/security`).

**JDKs inside IntelliJ or Android Studio** show under "Waiting on a vendor". Do not edit files inside the `.app` bundle (that breaks its signature). Set **Settings → Build Tools → Gradle → Gradle JVM** to a fixed JDK, and update the IDE when its vendor ships a new runtime. The script also checks the JDK named by `org.gradle.java.home` in `~/.gradle/gradle.properties`; commented-out lines are ignored.

## 4. Python, uv, Homebrew, Go and the rest

Most of these are one command each; the macOS system bundle is the exception and waits on Apple.

| Summary item | Fix |
| --- | --- |
| pip vendored certifi (pip 26.2.1 or older) | `python -m pip install -U pip` in that interpreter or virtualenv (Homebrew Python: `brew upgrade python`). pip always trusts its own copy, so this matters even with certifi updated. |
| Python `certifi` (older than 2026.10.19) | `python -m pip install -U certifi` in each virtualenv; pipx tools: `pipx upgrade-all` |
| uv older than 0.13.4 | `uv self update` (Homebrew: `brew upgrade uv`) |
| Homebrew bundle (`/opt/homebrew/etc/ca-certificates/cert.pem`) | `brew update && brew upgrade ca-certificates`, as the account that owns Homebrew |
| Go older than 1.26.10 / 1.27.3 | `brew upgrade go`, then rebuild Go binaries you ship to Linux or containers |
| Go binary in `~/go/bin` built with an old Go (advisory) | Rebuild it if it ships to Linux or uses its own root list; on macOS, Go uses Apple's verification |
| `/etc/ssl/cert.pem` (Waiting on a vendor) | Cannot be edited (System Integrity Protection). Install the next macOS update; until then prefer Homebrew `curl` over `/usr/bin/curl` |

**Before running `brew upgrade`:** it also upgrades or removes other formulae. In testing, `brew upgrade ca-certificates node@24` also installed `openssl@4`, uninstalled `python@3.13`, and upgraded `awscli` and `gnupg`. Run `brew upgrade --dry-run <formula>` first and check that nothing you depend on is removed.

Not checked by the script (listed under "Not covered"): Rust projects (`webpki-roots` 1.0.10+, `rustls-webpki` 0.103.16+), PHP projects (`composer/ca-bundle` 1.4.16+ or 1.6.0+), Docker images (rebuild on patched bases; Docker Desktop 4.96.2+), Bun 1.4.4+ and Deno 2.9.8+. Run `./jamf-emsign.sh --deep` once to find pip and certifi copies inside old virtualenvs; delete virtualenvs you no longer use instead of patching them.

## 5. Verify and report back

You are done when the summary says **STATUS: PROTECTED**, or **STATUS: VENDOR\_PENDING** with only `/etc/ssl/cert.pem` (waits on Apple) and IDE-bundled runtimes (wait on JetBrains or Google) under "Waiting on a vendor".

- [ ] Re-run `./jamf-emsign.sh --audit-only` and confirm "Fix now" is empty
- [ ] Post the STATUS line and counts from the summary to \<CHANNEL OR TICKET> by \<DEADLINE>
- [ ] Re-run after any `brew upgrade`, JDK install or new Node version until your vendors ship fixed builds

## For maintainers: the Jamf policy

The same `jamf-emsign.sh` runs as a Jamf policy script. As root, it does a system pass and then one pass per local user, each run as that user, so every account's Node, JDKs and Python are covered. Root never runs a program a user owns, and in remediate mode only Java is changed unattended: the four distrusted roots are removed from each unpatched JDK's `cacerts`, with a verified backup. IDE-bundled JDKs are never edited.

| Parameter | Purpose | Default |
| --- | --- | --- |
| $4 | `audit` or `remediate` | audit |
| $5 | Verbose log (`1`/`0`) | 1 |
| $6 | Mark the policy failed when EXPOSED or UNVERIFIED | yes |
| $7 | Run `jamf recon` afterwards | no |
| $8 | Scan `all` users or only the `console` user | all |

1. Add `jamf-emsign.sh` under **Settings → Computer management → Scripts** and label $4–$8 as above.
2. Add the extension attribute from the script header (also in `README.md`). It reads `/Library/Application Support/emsign-check/status.plist`, so inventory updates do not rescan. Build smart groups on EXPOSED and UNVERIFIED.
3. Test on one Mac first; `sudo` takes the same code path as Jamf:

   ```bash
   sudo ./jamf-emsign.sh / "$(hostname)" "$USER" audit
   sudo ./jamf-emsign.sh / "$(hostname)" "$USER" remediate 1 no no console
   sudo ./jamf-emsign.sh --mode=audit --verbose --users=console   # same, with flags
   ```
4. Roll out in **audit** mode; nothing changes, and each Mac's log and status file list what remediate would do.
5. Switch $4 to **remediate** to fix Java fleet-wide. Node, Homebrew, pip and uv stay with developers (downloads and brew side effects); they appear under "Fix now" in each Mac's log and in the status file. Keep the policy recurring: JDK updates restore the old `cacerts` until each Mac has a fixed build.

Exit codes in Jamf: 0 for PROTECTED or VENDOR_PENDING; 1 for EXPOSED or UNVERIFIED when $6 is `yes`; 2 for bad parameters or when the script could not run.

Limits: Jamf runs do not load shell profiles, so variables a developer exports there (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `JAVA_HOME`) are only seen when developers run the script themselves. Logs: the policy log and `/var/log/emsign-check.log`.

## For maintainers: running the tests

Run the test suite after any change to the script and before uploading a new version to Jamf:

```bash
tests/run-tests.sh                         # tests ./jamf-emsign.sh
tests/run-tests.sh path/to/jamf-emsign.sh  # tests another copy
```

It needs bash, `openssl` and `perl`, and runs on macOS or Linux without root. The Java cases use a real `keytool` (any JDK 9+ on `PATH` or `JAVA_HOME`) and are reported as skipped without one. All test input is generated in a temporary directory that is deleted afterwards. The run ends with `RESULT: N passed, N failed, N skipped` and exits 0 only when nothing failed. The fixtures in `tests/fixtures/` are public root certificates only.

## FAQ

**My browser is fine, so why does this matter?** Builds, package installs and API clients run outside the browser. A forged certificate could serve a tampered package to `npm install` or a Gradle build on an untrusted network.

**Do I need to replace our own certificates?** No, unless they were issued by eMudhra/emSign. This is about what your tools trust, not what they present.

**Why does a file with only AAA Certificate Services fail?** Sectigo cross-signed all eight compromised intermediates under AAA. Tools that read a CA file directly (curl, Python, Ruby) do not check revocation, so AAA in such a file accepts the compromised chains. Java follows the same logic: Oracle's fixed builds remove AAA from `cacerts`.

**Will the fix break anything?** In Java, sites whose only chain runs to one of the four removed roots stop validating, which is the same result Oracle's fixed JDKs give. The backup next to `cacerts` restores the previous state if you need it while you investigate.

**What does "affected-looking names with unrecognized keys" mean?** A certificate is named like an affected one but its key does not match the published identities. The script sends it to Review rather than guessing; compare its fingerprint with the disclosure site.

## Sources

- [eMudhra Intermediate CA Compromise – disclosure, fixed versions and certificate identities](https://emudhra.we-have-a-problem.com/)
- [Oracle: Distrusting eMudhra intermediates in the JDK](https://ops.java/emudhra)
- [Corretto 21 issue #174: 21.0.13.0.10 fix](https://github.com/corretto/corretto-21/issues/174)
- [Node.js 24.22.1 release](https://nodejs.org/en/blog/release/v24.22.1)
- [Python Discourse: guidance for pip, certifi and uv](https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576)
- [pip changelog: 26.2.2 updates certifi](https://pip.pypa.io/en/latest/news/)
- [BellSoft: removing roots vs. the blocklist in Java](https://bell-sw.com/blog/distrusting-compromised-emudhra-intermediates-in-java/)
