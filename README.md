# eMudhra Certificate Remediation: Developer Mac Guide

Oct 21, 2026 · @Lucas

## What happened

Every developer Mac needs its Node, Java and Python trust stores updated this week; browsers are already protected. On 17 October 2026 the private keys of eight eMudhra certificate authorities were found to be trivially weak. Anyone holding them can mint a certificate for any site that an unpatched tool will accept.

Safari, Chrome and Firefox blocked the certificates within days. Command-line tools and language runtimes carry their own copy of trusted roots and do not check revocation, so they still trust forged certificates until updated:

- **Node.js** (npm, Yarn): fixed releases shipped 21 October.
- **Java**: every JDK, including the ones bundled inside IntelliJ and Android Studio.
- **Python**: Homebrew's CA bundle and certifi inside each virtualenv.
- **Go**: fixed in 1.26.10 and 1.27.3; binaries built with older toolchains need a rebuild.

The root on the compromised path is **emSign ECC Root CA - G3**. Other emSign roots (G1, C1, ECC C3) are not affected.

Fix time: about 20–30 minutes per machine.

## 1. Run the audit

Run the audit script first. If it finds problems, it asks whether to fix them and confirms each change before making it, so most machines need nothing else. Sections 2–4 are the manual steps it automates, for anything it skips or can't do.

```bash
# Get emsign-check.sh from: <INTERNAL LOCATION – repo, wiki or Self Service>
chmod +x emsign-check.sh

# Oracle's site rejects scripted downloads, so the script fetches the Java
# blocklist from our internal mirror and checks its hash:
export BLOCKED_CERTS_URL="<INTERNAL MIRROR URL>/blocked.certs"
export BLOCKED_CERTS_SHA256="<SHA-256 FROM THE TEAM>"

./emsign-check.sh          # add --deep to also scan virtualenvs and vendored bundles
```

- Answer **y** to "Proceed to remediation?", then y or n to each fix. It backs up every Java file it changes as `*.bak-<timestamp>`.
- It skips the JDKs bundled in IntelliJ and Android Studio and anything needing admin rights you decline; those show under **Manual steps**.
- It re-runs the audit at the end to verify. Use `--audit-only` to just report.

The result is one of three states:

| Result | Exit code | Meaning |
| --- | --- | --- |
| CLEAN | 0 | Nothing to do |
| WARN | 1 | OS-managed items or mitigations to review; no action unless listed below |
| EXPOSED | 2 | At least one runtime still trusts the compromised chain |

Find each FAIL line's section heading (Node.js, Java, Python, Go) and apply the matching fix.

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

## 3. Java (JDK 21 and any other JDK)

No patched JDK has shipped yet, so remove the affected root from each JDK the audit flags and install Oracle's updated blocklist. Java does not check revocation by default, so both steps matter.

1. Remove the root from the JDK's `cacerts`. Use the JDK path and the alias the audit printed on the FAIL line:

   ```bash
   JH="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"   # the flagged JDK
   "$JH/bin/keytool" -list -cacerts -storepass changeit | grep -i emsign
   "$JH/bin/keytool" -delete -cacerts -storepass changeit -alias "<alias from audit>"
   ```
2. Install Oracle's updated `blocked.certs` from our internal mirror, the same copy the script uses, and confirm its hash before installing. It blocks the eight keys themselves, which also covers the Sectigo cross-signed copies that root removal cannot. Don't curl it from Oracle directly: ops.java answers scripted requests with 403 Forbidden. If the mirror is down, download the non-Windows file in a browser from [ops.java/emudhra](https://ops.java/emudhra) and check its hash the same way.

   ```bash
   curl -fsSL -o /tmp/blocked.certs "<INTERNAL MIRROR URL>/blocked.certs"
   shasum -a 256 /tmp/blocked.certs          # must equal <SHA-256 FROM THE TEAM>
   cp "$JH/lib/security/blocked.certs" "$JH/lib/security/blocked.certs.bak"
   cp /tmp/blocked.certs "$JH/lib/security/blocked.certs"
   ```
3. Restart Gradle daemons so builds pick up the change: `./gradlew --stop`.
4. Re-run the audit. `brew upgrade` reinstalls a fresh `cacerts`, so repeat steps 1–2 after any JDK upgrade until a fixed JDK ships.

**JDKs inside IntelliJ or Android Studio:** do not edit files inside the `.app` bundle, since that can break its code signature and updates. Instead, set **Settings → Build Tools → Gradle → Gradle JVM** to the JDK you fixed, and update the IDE when JetBrains or Google ships a new runtime.

**Optional hardening:** add `-Dcom.sun.net.ssl.checkRevocation=true -Dcom.sun.security.enableCRLDP=true` to `JAVA_TOOL_OPTIONS`. Test it first, because connections fail where CRL endpoints are unreachable.

## 4. Python, Homebrew, Go and the rest

Most of these are one command each; the macOS system bundle is the exception and waits on Apple.

| Audit FAIL/WARN | Fix |
| --- | --- |
| Homebrew bundle (`/opt/homebrew/etc/ca-certificates/cert.pem`) | `brew update && brew upgrade ca-certificates` |
| Python `ssl default` | Same as above; Homebrew Python uses that bundle |
| Python `certifi` (older than 2026.10.19) | In each virtualenv: `pip install -U certifi`; pipx tools: `pipx upgrade-all` |
| Go older than 1.26.10 / 1.27.3 | `brew upgrade go`, then rebuild any Go binaries you built or installed with `go install` |
| Rust projects | `cargo update -p webpki-roots` (needs 1.0.10 or later) |
| Docker images | Rebuild on updated base images; containers do not use your Mac's trust |
| `/etc/ssl/cert.pem` (WARN, OS-managed) | Cannot be edited (System Integrity Protection). Install the next macOS update when it ships; until then prefer Homebrew `curl` over `/usr/bin/curl` |

Run `./emsign-check.sh --deep` once to find certifi copies inside old virtualenvs and app bundles; delete virtualenvs you no longer use instead of patching them.

## 5. Verify and report back

You are done when the audit ends in CLEAN, or in WARN where the only warnings are `/etc/ssl/cert.pem` (waits on Apple) and IDE-bundled runtimes (wait on JetBrains or Google). If the script reports a `blocked.certs` download failure, check that `BLOCKED_CERTS_URL` and `BLOCKED_CERTS_SHA256` are set as in step 1. As a fallback, download the file in a browser from [ops.java/emudhra](https://ops.java/emudhra) and run `BLOCKED_CERTS_FILE=~/Downloads/blocked.certs ./emsign-check.sh`.

- [ ] Re-run `./emsign-check.sh` and confirm no FAIL lines
- [ ] Post the final `Result:` line to \<CHANNEL OR TICKET> by \<DEADLINE>
- [ ] Re-run after any `brew upgrade`, JDK install or new Node version until fixed JDKs ship

## For maintainers: hosting the Java blocklist

Host one vetted copy of Oracle's `blocked.certs` internally, so every Mac installs the identical file; ops.java rejects scripted downloads with 403.

1. Download the non-Windows `blocked.certs` from [ops.java/emudhra](https://ops.java/emudhra) in a browser.
2. Commit it to an internal repo or web server, and record its hash: `shasum -a 256 blocked.certs`.
3. Fill in `<INTERNAL MIRROR URL>` and `<SHA-256 FROM THE TEAM>` in this guide, or set them as defaults in the script or your MDM/Self Service wrapper.
4. When Oracle updates the file, repeat steps 1–3. The script refuses any file whose hash does not match `BLOCKED_CERTS_SHA256`.

## FAQ

**My browser is fine, so why does this matter?** Builds, package installs and API clients run outside the browser. A forged certificate could serve a tampered package to `npm install` or a Gradle build on an untrusted network.

**Do I need to replace our own certificates?** No, unless they were issued by eMudhra/emSign. This is about what your tools trust, not what they present.

**Will removing the root break anything?** Only sites with eMudhra G3-chain certificates, which eMudhra has stopped issuing. Internal and DoD CAs are unaffected.

**The audit flags an emSign root I left alone.** Only emSign ECC Root CA - G3 is flagged as affected; tell \<CONTACT> if anything else shows as FAIL.

## Sources

- [eMudhra Intermediate CA Compromise – disclosure and fixed-version list](https://emudhra.we-have-a-problem.com/)
- [Oracle: Distrusting eMudhra intermediates in the JDK](https://ops.java/emudhra)
- [easyDNS advisory: Node.js security releases, 21 Oct 2026](https://easydns.com/blog/2026/10/21/customer-security-advisory-critical-updates-for-php-node-js-and-certificate-trust/)
- [Root store analysis: which emSign roots are on the affected path](https://gist.github.com/UlisesGascon/10ed0724930e5382b3ed48fa2b0d3e02)
- [Mozilla bug 2083709: emSign C1 and ECC C3 retirement](https://bugzilla.mozilla.org/show_bug.cgi?id=2083709)
