# eMudhra Certificate Remediation: Developer Mac Guide

Oct 23, 2026 · @Lucas

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
```

- Nothing to download: Oracle's Java blocklist is built into the script.
- Answer **y** to "Proceed to remediation?", then y or n to each fix. Java files are backed up as `*.bak-<timestamp>` before any change.
- `--yes` approves the routine fixes only. Removing old Node versions or Java roots still needs your interactive answer (or `--allow-destructive`).
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

A JDK is fixed when its blocklist blocks all 16 compromised certificates (the 8 intermediates, each issued by emSign and cross-signed by Sectigo). The script checks the blocklist itself, so a patched vendor JDK passes even though the emSign root is still in its `cacerts`. That is expected.

Fix in this order, as Oracle recommends:

1. **Install a patched JDK** where your vendor has one: Oracle/OpenJDK 8u511, 11.0.33.0.2, 17.0.21.0.2, 21.0.13.0.2, 25.0.5.0.2 or 27.0.1.0.2; Corretto 21.0.13.0.10. Homebrew's `openjdk@21` 21.0.13 is not a fixed build yet.
2. **Otherwise let the script merge Oracle's blocklist.** Answer y to "Merge Oracle's blocklist". It writes the file that JDK actually reads (`lib/security/blocked.certs`; on Java 8, `jre/lib/security/blacklisted.certs`), keeps a backup, and verifies all 16 entries afterwards. Then restart Gradle daemons: `./gradlew --stop`.
3. **Optionally add revocation checking:** `-Dcom.sun.net.ssl.checkRevocation=true -Dcom.sun.security.enableCRLDP=true` in `JAVA_TOOL_OPTIONS`. Test it first; connections fail where CRL endpoints are unreachable.
4. **Root removal is a last resort**, never needed once step 1 or 2 is done. With `--remove-roots` the script offers to delete the emSign G3 root alias(es), matched by key, and asks you separately each time. It never removes AAA Certificate Services, which anchors unrelated Sectigo chains.

JDK upgrades replace the blocklist, so re-run the script after each one until your vendor ships a fixed build.

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

The same `jamf-emsign.sh` runs as a Jamf policy script. As root, it does a system pass and then one pass per local user, each run as that user, so every account's Node, JDKs and Python are covered. Root never runs a program a user owns, and in remediate mode only Java is changed unattended.

| Parameter | Purpose | Default |
| --- | --- | --- |
| $4 | `audit` or `remediate` | audit |
| $5 | Newer Oracle blocklist URL (only if Oracle updates the file) | built-in list |
| $6 | SHA-256 of that file (required with $5) | — |
| $7 | Verbose log (1/0) | 1 |
| $8 | Mark the policy failed when EXPOSED or UNVERIFIED | yes |
| $9 | Run `jamf recon` afterwards | no |
| $10 | Scan `all` users or only the `console` user | all |
| $11 | Also remove emSign G3 roots from unpatched JDKs | no |

1. Test on one Mac first: `sudo ./jamf-emsign.sh / "$(hostname)" "$USER" audit "" "" 1 no no console`.
2. Roll out in **audit** mode. Each run writes `/Library/Application Support/emsign-check/status.plist`; the extension attribute in the script header reads it, so inventory updates do not rescan. Build smart groups on EXPOSED and UNVERIFIED.
3. Switch $4 to **remediate** to fix Java fleet-wide. Node, Homebrew, pip and uv stay with developers (downloads and brew side effects); they appear under "Fix now" in each Mac's log and in the status file.

Limits: Jamf runs do not load shell profiles, so variables a developer exports there (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `JAVA_HOME`) are only seen when developers run the script themselves. Logs: the policy log and `/var/log/emsign-check.log`.

## FAQ

**My browser is fine, so why does this matter?** Builds, package installs and API clients run outside the browser. A forged certificate could serve a tampered package to `npm install` or a Gradle build on an untrusted network.

**Do I need to replace our own certificates?** No, unless they were issued by eMudhra/emSign. This is about what your tools trust, not what they present.

**Why does a file with only AAA Certificate Services fail?** Sectigo cross-signed all eight compromised intermediates under AAA. Tools that read a CA file directly (curl, Python, Ruby) do not check revocation, so AAA in such a file accepts the compromised chains. Java is judged by its blocklist instead, because patched JDKs keep AAA.

**Will the fix break anything?** The blocklist rejects only the 16 compromised certificates. Root removal is optional and only ever targets emSign G3 roots, which eMudhra no longer issues under.

**What does "affected-looking names with unrecognized keys" mean?** A certificate is named like an affected one but its key does not match the published identities. The script sends it to Review rather than guessing; compare its fingerprint with the disclosure site.

## Sources

- [eMudhra Intermediate CA Compromise – disclosure, fixed versions and certificate identities](https://emudhra.we-have-a-problem.com/)
- [Oracle: Distrusting eMudhra intermediates in the JDK](https://ops.java/emudhra)
- [Corretto 21 issue #174: 21.0.13.0.10 fix](https://github.com/corretto/corretto-21/issues/174)
- [Node.js 24.22.1 release](https://nodejs.org/en/blog/release/v24.22.1)
- [Python Discourse: guidance for pip, certifi and uv](https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576)
- [pip changelog: 26.2.2 updates certifi](https://pip.pypa.io/en/latest/news/)
- [BellSoft: removing roots vs. the blocklist in Java](https://bell-sw.com/blog/distrusting-compromised-emudhra-intermediates-in-java/)
