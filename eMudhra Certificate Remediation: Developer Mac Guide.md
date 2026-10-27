# eMudhra Certificate Remediation: Developer Mac Guide

Oct 27, 2026 · @Lucas

**Guide v3.1.4**, for `jamf-emsign.sh` **v3.1.4**. Check your copy with `grep '^VERSION=' jamf-emsign.sh`; if it differs, get the matching script or guide from [jamf-emsign-v3.1.4](https://github.com/Widget-Ninja/check-local-certs/tree/main).

## What happened

Every developer Mac needs its Node, Java and Python trust stores updated this week; browsers are already protected. On 17 October 2026 the private keys of eight eMudhra certificate authorities were found to be trivially weak. Anyone holding them can mint a certificate for any site that an unpatched tool will accept.

Safari, Chrome and Firefox blocked the certificates within days. Command-line tools and language runtimes carry their own copy of trusted roots and do not check revocation, so they still trust forged certificates until updated:

- **Node.js** (npm, Yarn): fixed releases shipped 21 October.
- **Java**: every JDK, including Gradle toolchain JDKs and the runtimes bundled inside JetBrains IDEs and Android Studio.
- **Python**: pip (its own built-in certificate list), certifi in each virtualenv, and Homebrew's CA bundle.
- **uv**, **Go** (1.26.10 / 1.27.3; rebuild binaries you ship) and any file-based CA bundle.

The compromised intermediates chain to **emSign ECC Root CA - G3** and, through Sectigo cross-signs, to **AAA Certificate Services**. The script recognizes certificates by their public keys, not their names, so a renamed copy is still caught. For Java, Oracle went further on 24 October and also removed **emSign Root CA - G1** and **G2** from the JDK (section 3); in other CA files, G1, C1 and ECC C3 are not affected.

Fix time: about 20–30 minutes per machine.

## 1. Run the script

Run `jamf-emsign.sh` as yourself (not with sudo): it audits first, then offers fixes and confirms each one, so most Macs need nothing else. Sections 2–4 are the manual steps behind each fix.

```bash
# Get jamf-emsign.sh from: <INTERNAL LOCATION – repo, wiki or Self Service>
chmod +x jamf-emsign.sh
./jamf-emsign.sh                 # audit, then offer fixes (asks before each one)
./jamf-emsign.sh --audit-only    # report only, change nothing
./jamf-emsign.sh --deep          # also scan virtualenvs and app-bundled CA files
```

- Nothing to download: the certificate identities the script checks are built in.
- Answer **y** to "Proceed to remediation?", then y or n to each fix. A JDK's `cacerts` is backed up as `cacerts.emsign-bak-<timestamp>` before any change.
- `--yes` approves the fixes, including Java root removal. Removing old Node versions still needs your interactive answer (or `--allow-destructive`).
- Run it from any folder; npm and Yarn are never started inside your projects, so a pinned package manager cannot stall it.

The run ends with a **SUMMARY** block: a STATUS line, then **Fix now** (each item with its fix), **Waiting on a vendor**, and **Review**.

| STATUS | Exit code (your run) | What it means for you |
| --- | --- | --- |
| PROTECTED | 0 | Done |
| VENDOR\_PENDING | 1 | Done for now; what is left waits on Apple or an IDE vendor |
| EXPOSED | 2 | Work through **Fix now** |
| UNVERIFIED | 3 | Something could not be checked; follow **Review**, or send the summary to \<Support Team> |

WARN lines are advisories and never change the status. "Not covered" lists what the script cannot check; it is not counted. A Jamf run uses the same STATUS names but different exit codes (see the maintainers section).

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

With Homebrew: `brew upgrade node` (or `node@24 or node@26`).

**If you set** `NODE_OPTIONS=--use-system-ca`: Node versions before 22.15 refuse to start with it, so remove those versions. The flag also pulls in macOS's roots, and Apple's revocation does not protect Node, so the upgrade is still required.

After upgrading, delete and reinstall `node_modules` only if a project pins an `engines` range the new version breaks; the fix itself needs no reinstall.

**Extra CA files:** a patched Node rejects the compromised certificates even if `NODE_EXTRA_CA_CERTS` adds AAA or emSign roots, so the script only notes that file once every Node on the Mac is patched. **Corepack:** if a project pins an older npm or Yarn (`"packageManager"` in `package.json`), Corepack asks before downloading it; run `npm` once inside that project and answer the prompt, or update the pin.

## 3. Java (JDK 21 and any other JDK)

A JDK is fixed when its `cacerts` no longer trusts the four roots Oracle removed on 24 October (CVE-2026-114820): **emSign ECC Root CA - G3**, **emSign Root CA - G1**, **emSign Root CA - G2** and **AAA Certificate Services**. The script matches them by key. Oracle now lists the 21 October builds, which only added a blocklist, as affected, so a complete blocklist no longer passes on its own; the script still shows it for context.

Fix in this order:

1. **Install a fixed JDK** where your vendor has one: Oracle 8u511-b33, 11.0.33.0.3, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3 or 27.0.1.0.3, or any vendor build that includes JDK-8395690. Corretto 21.0.13.0.10 shipped before this change, so it still needs step 2.
2. **Otherwise let the script remove the four roots.** Answer y to "Remove … distrusted root(s)". It removes only the entries whose key matches, keeps a verified backup next to `cacerts`, edits a copy, checks the copy, and only then swaps it in. Then restart Gradle daemons: `./gradlew --stop`. To undo, copy the backup over `cacerts`.
3. **Revocation checking** is Oracle's other option: `-Dcom.sun.net.ssl.checkRevocation=true -Dcom.sun.security.enableCRLDP=true` in `JAVA_TOOL_OPTIONS`. The script notes it but does not count it as the fix, because it only covers processes that inherit the variable. Test it first; connections fail where CRL endpoints are unreachable.

A JDK update installs a fresh `cacerts`, so re-run the script after each update until you are on a fixed build.

**Runtimes inside JetBrains IDEs** (IntelliJ, PyCharm, GoLand and the rest, including Toolbox installs) **or Android Studio** show under "Waiting on a vendor". Do not edit files inside the `.app` bundle (that breaks its signature). Set **Settings → Build Tools → Gradle → Gradle JVM** to a fixed JDK, and update the IDE when its vendor ships a new runtime. The script also checks Gradle toolchain JDKs in `~/.gradle/jdks` and the JDK named by `org.gradle.java.home` in `~/.gradle/gradle.properties`; commented-out lines are ignored.

## 4. Python, uv, Homebrew, Go and the rest

Most of these are one command each; the macOS system bundle is the exception and waits on Apple.

| Summary item | Fix |
| --- | --- |
| pip vendored certifi (pip 26.2.1 or older) | `python -m pip install -U pip` in that interpreter or virtualenv (Homebrew Python: `brew upgrade python`; uv-managed Python: `uv python upgrade`). pip always trusts its own copy, so this matters even with certifi updated. |
| Python `certifi` (older than 2026.10.19) | `python -m pip install -U certifi` in each virtualenv; pipx tools: `pipx upgrade-all` |
| pip or certifi in Apple's Python (/usr/bin/python3, Xcode, Command Line Tools) (Waiting on a vendor) | Waits on an Xcode or Command Line Tools update. Do not change files inside Xcode (it breaks its signature and the next update undoes it). Use Homebrew or uv Python for your own work. |
| uv older than 0.13.5 | `uv self update` (Homebrew: `brew upgrade uv`), then `uv python upgrade` for the Pythons uv installed. 0.13.4 only dropped the emSign root; 0.13.5 also blocks the AAA cross-signed path. |
| Homebrew bundle (`/opt/homebrew/etc/ca-certificates/cert.pem`) | `brew update && brew upgrade ca-certificates`, as the account that owns Homebrew |
| Go older than 1.26.10 / 1.27.3 | `brew upgrade go`, then rebuild Go binaries you ship to Linux or containers |
| Go binary in `~/go/bin` built with an old Go (advisory) | Rebuild it if it ships to Linux or uses its own root list; on macOS, Go uses Apple's verification |
| `/etc/ssl/cert.pem`, also reported for Apple's built-in Python and Ruby (Waiting on a vendor) | Apple will fix it in a future macOS update (no date yet). Until then prefer Homebrew `curl`, `git`, Python and Ruby over the system ones. Apple documents an optional manual edit for admins (remove emSign ECC Root CA - G3, optionally AAA, from the file); a macOS update can undo it, and tools using only this file may then fail on some sites. |
| Admin or user trust settings: an emSign or AAA certificate marked trusted | Keychain Access → find the certificate named in the summary → Trust → Use System Defaults. If a configuration profile set it, ask \<CONTACT> to remove that profile instead. |

**Before running `brew upgrade`:** it also upgrades or removes other formulae. In testing, `brew upgrade ca-certificates node@24` also installed `openssl@4`, uninstalled `python@3.13`, and upgraded `awscli` and `gnupg`. Run `brew upgrade --dry-run <formula>` first and check that nothing you depend on is removed.

Not checked by the script (listed under "Not covered"): Rust projects (`webpki-roots` 1.0.10+, `rustls-webpki` 0.103.16+), PHP projects (`composer/ca-bundle` 1.4.16+ or 1.6.0+), Docker images (rebuild on patched bases; Docker Desktop 4.96.2+), Bun 1.4.4+ and Deno 2.9.8+. Run `./jamf-emsign.sh --deep` once to find pip and certifi copies inside old virtualenvs; delete virtualenvs you no longer use instead of patching them.

## 5. Verify and report back

You are done when the summary says **STATUS: PROTECTED**, or **STATUS: VENDOR\_PENDING** with only these under "Waiting on a vendor": `/etc/ssl/cert.pem` and Apple's Python (wait on Apple), and IDE-bundled runtimes (wait on JetBrains or Google).

- [ ] Re-run `./jamf-emsign.sh --audit-only` and confirm "Fix now" is empty
- [ ] Re-run after any `brew upgrade`, JDK install or new Node version until your vendors ship fixed builds

## For maintainers: the Jamf policy

The same `jamf-emsign.sh` runs as a Jamf policy script. As root, it does a system pass and then one pass per local user, each run as that user, so every account's Node, JDKs and Python are covered. Root only runs a program that is owned by root, sits in folders only root can write to, and (for a JDK, Python or Ruby) has nothing writable by others inside its install folder; for a JDK both `java` and `keytool` are checked. Apple's Python is never run as root. Anything root refuses is checked by the user passes instead. In remediate mode only Java is changed unattended.

| Parameter | Purpose | Default |
| --- | --- | --- |
| $4 | `audit` or `remediate` | audit |
| $5 | Verbose log (1/0) | 1 |
| $6 | Mark the policy failed when EXPOSED or UNVERIFIED | yes |
| $7 | Run `jamf recon` afterwards | no |
| $8 | Scan `all` users or only the `console` user | all |

1. Test on one Mac first: `sudo ./jamf-emsign.sh / "$(hostname)" "$USER" audit 1 no no console`.
2. Roll out in **audit** mode. Each run writes `/Library/Application Support/emsign-check/status.plist`; the extension attribute in the script header reads it, so inventory updates do not rescan. Build smart groups on EXPOSED and UNVERIFIED.
3. Switch $4 to **remediate** to fix Java fleet-wide: each JDK that still trusts the four roots has exactly those entries removed, with a verified backup next to its `cacerts`. Node, Homebrew, pip and uv stay with developers (downloads and brew side effects); they appear under "Fix now" in each Mac's log and in the status file.

Exit codes of a Jamf run: **0** = PROTECTED or VENDOR\_PENDING; **1** = EXPOSED or UNVERIFIED when $6 is yes (with no, these also exit 0); **2** = bad parameters or the script could not run. Developer runs use 0–3 (section 1). The status file keeps the full Failures and Actions lists.

Limits: Jamf runs do not load shell profiles, so CA settings a developer exports there (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `JAVA_TOOL_OPTIONS`) are only checked when developers run the script themselves; each Jamf run lists this under "Not covered". Logs: the policy log and `/var/log/emsign-check.log`.

## FAQ

**My browser is fine, so why does this matter?** Builds, package installs and API clients run outside the browser. A forged certificate could serve a tampered package to `npm install` or a Gradle build on an untrusted network.

**Do I need to replace our own certificates?** No, unless they were issued by eMudhra/emSign. This is about what your tools trust, not what they present.

**Why does a file with only AAA Certificate Services fail?** Sectigo cross-signed all eight compromised intermediates under AAA. Tools that read a CA file directly (curl, Python, Ruby) do not check revocation, so AAA in such a file accepts the compromised chains. Since Oracle's 24 October update the same applies to Java: AAA has to be gone from `cacerts` too.

**Will the fix break anything?** Removing the four roots from a JDK is the same change Oracle's 24 October builds make. AAA Certificate Services is an old Sectigo root and most Sectigo sites also chain to roots that stay, but a service that only chains to AAA will stop working in Java. If a build fails with a certificate path error afterwards, send the error to \<Support Team>; the backup next to `cacerts` undoes the change.

**What does "affected-looking names with unrecognized keys" mean?** A certificate is named like an affected one but its key does not match the published identities. The script sends it to Review rather than guessing; compare its fingerprint with the disclosure site.

**Why does a trust setting show as a FAIL?** Marking a certificate Always Trust in Keychain Access (yourself, or through a configuration profile) overrides Apple's block. The script reads the actual setting for emSign and AAA certificates in the admin and user trust settings: Always Trust is a FAIL; Never Trust or Use System Defaults passes; a setting it cannot read goes to Review. Apple's built-in root list is not an override and is never flagged.

## Sources

- [eMudhra Intermediate CA Compromise – disclosure, fixed versions and certificate identities](https://emudhra.we-have-a-problem.com/)
- [Oracle: Distrusting eMudhra intermediates in the JDK](https://ops.java/emudhra)
- [Oracle Security Alert CVE-2026-114820 (24 October 2026)](https://www.oracle.com/security-alerts/alert-cve-2026-114820.html)
- [Oracle JDK 21.0.13.0.3 release notes: the four roots removed](https://www.oracle.com/java/technologies/javase/21-0-13-0-3-relnotes.html)
- [Corretto 21 issue #174: 21.0.13.0.10 fix](https://github.com/corretto/corretto-21/issues/174)
- [Node.js 24.22.1 release](https://nodejs.org/en/blog/release/v24.22.1)
- [Python Discourse: guidance for pip, certifi and uv](https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576)
- [pip changelog: 26.2.2 updates certifi](https://pip.pypa.io/en/latest/news/)
- [BellSoft: removing roots vs. the blocklist in Java](https://bell-sw.com/blog/distrusting-compromised-emudhra-intermediates-in-java/)
