#!/bin/bash
# Test suite for jamf-emsign.sh. Bash only; scenarios ported from the v2.3.0
# suite where they apply, plus the Oracle 2026-10-24 Java policy and the
# root-removal transaction. Each case runs in a fresh subshell that sources the
# script (sourcing loads functions only; it never starts a pass).
#
#   tests/run-tests.sh [path/to/jamf-emsign.sh]
#
# Needs openssl and perl. Java cases use a real keytool (any JDK 9+ on PATH or
# JAVA_HOME); without one they are reported as skipped.
# Each case is stopped after CASE_TIMEOUT seconds (default 30; the slowest takes
# about 8s) and reported as a failure, so a hang never stalls the run. Nothing outside a
# temporary directory is read as test input or changed.
HERE=$(cd "$(dirname "$0")" && pwd)
S=${1:-$HERE/../jamf-emsign.sh}
S=$(cd "$(dirname "$S")" && pwd)/$(basename "$S")
FIX=$HERE/fixtures
[ -f "$S" ] || { echo "script not found: $S" >&2; exit 2; }
for f in aaa.pem emsign-g1.pem emsign-g2.pem emsign-g3.pem; do
  [ -f "$FIX/$f" ] || { echo "missing fixture $FIX/$f" >&2; exit 2; }
done
TOP=$(mktemp -d "${TMPDIR:-/tmp}/emsign-tests.XXXXXX"); trap 'rm -rf "$TOP"' EXIT
NPASS=0; NFAIL=0; NSKIP=0; FAILED=()
export FIX TOP S

# ---- shared inputs ---------------------------------------------------------
# Look-alike: emSign G3's name on an unrelated key. Plus a clean, unrelated CA.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes -keyout "$TOP/lookalike.key" \
  -subj "/C=IN/OU=emSign PKI/O=eMudhra Technologies Limited/CN=emSign ECC Root CA - G3" -days 30 -out "$TOP/lookalike.pem" 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TOP/other.key" -subj "/CN=Unrelated Test Root" -days 30 -out "$TOP/other.pem" 2>/dev/null
openssl x509 -in "$FIX/aaa.pem" -outform DER -out "$TOP/aaa.der"

KEYTOOL=""; JAVA=""
for c in "${JAVA_HOME:-}/bin/keytool" "$(command -v keytool 2>/dev/null)"; do
  [ -n "$c" ] && [ -x "$c" ] || continue
  c=$(perl -MCwd=abs_path -e 'print abs_path(shift)' "$c")
  [ -x "$(dirname "$c")/java" ] && "$c" -help >/dev/null 2>&1 && { KEYTOOL=$c; JAVA="$(dirname "$c")/java"; break; }
done
export KEYTOOL JAVA

# ---- helpers available inside cases ------------------------------------------
tnote() { printf '%s ' "$*" >> "$T/extra"; }          # extra observation shown with the counters
# mkjdk HOME [alias=pemfile ...]: a JDK home whose bin/ points at the real keytool
# and java, with a cacerts holding exactly the given entries. LAYOUT8=1 -> jre/lib/security.
mkjdk() {
  local jh=$1 sec spec; shift
  sec="$jh/lib/security"; [ "${LAYOUT8:-0}" = 1 ] && sec="$jh/jre/lib/security"
  mkdir -p "$jh/bin" "$sec"
  ln -sf "$KEYTOOL" "$jh/bin/keytool"; ln -sf "$JAVA" "$jh/bin/java"
  for spec in "$@"; do
    "$KEYTOOL" -importcert -noprompt -storetype PKCS12 -storepass changeit -keystore "$sec/cacerts" \
      -alias "${spec%%=*}" -file "${spec#*=}" >/dev/null 2>&1 || echo "mkjdk: import ${spec%%=*} failed" >&2
  done
}
ALL4=("comodoaaaca [jdk]=$FIX/aaa.pem" "emsignrootcag1 [jdk]=$FIX/emsign-g1.pem" "emsignrootcag2 [jdk]=$FIX/emsign-g2.pem" "emsigneccrootcag3 [jdk]=$FIX/emsign-g3.pem")
aliases_in() { "$KEYTOOL" -list -keystore "$1" -storepass changeit 2>/dev/null | awk -F', ' '/trustedCertEntry/ { print $1 }' | sort | paste -sd';' -; }
fullbl() { { echo "Algorithm=SHA-256"; emudhra_fingerprints; } > "$1"; }
export -f tnote mkjdk aliases_in fullbl

# case_ NAME EXPECT_REGEX FUNCTION
# Output compared: "P=pass F=fail D=pending U=unverified W=advisory E=errors <tnote...>"
# run_one FUNCTION: one case in a fresh state (called in a subshell by case_).
# Kept as a top-level function: bash 3.2 (macOS) cannot parse a case statement
# inside $( ... ), so nothing with a case pattern may live in a substitution.
run_one() {
  local fn=$1
  T=$(mktemp -d "$TOP/c.XXXXXX"); export T HOME="$T/home"; mkdir -p "$HOME"; cd "$T" || exit
  unset NODE_EXTRA_CA_CERTS SSL_CERT_FILE SSL_CERT_DIR REQUESTS_CA_BUNDLE CURL_CA_BUNDLE GIT_SSL_CAINFO PIP_CERT \
        NODE_OPTIONS npm_config_cafile NPM_CONFIG_CAFILE JAVA_HOME JAVA_TOOL_OPTIONS JDK_JAVA_OPTIONS _JAVA_OPTIONS \
        NODE_TLS_REJECT_UNAUTHORIZED GIT_SSL_NO_VERIFY PIP_TRUSTED_HOST \
        NVM_DIR npm_config_strict_ssl NPM_CONFIG_STRICT_SSL GIT_CONFIG_GLOBAL
  # (NVM_DIR etc. point at the developer's real installs; each case uses its own HOME.)
  # shellcheck disable=SC1090
  source "$S" >/dev/null 2>&1 || { echo SOURCE_FAILED; exit; }
  ROLE=dev; MODE=audit; VERBOSE=0; YES=0; COLOR=0
  PASS=0; WARN=0; FAIL=0; PEND=0; UNV=0; ERRORS=0; FIXED=0; SKIPPED=0
  SEEN=""; BUNDLE_CACHE=""; RESULTS=(); ACTIONS=(); NOT_COVERED=(); MANUAL=()
  NODE_FIX=(); JDK_FIX=(); CERTIFI_FIX=(); PIP_FIX=(); UV_FIX=(); BREW_PKGS=""; KS_ROOTS=""
  security() { return 1; }
  # Only runtimes this case created count; the machine's own installs are ignored.
  mine() { case "$1" in "$T"/*) return 0 ;; *) return 1 ;; esac; }
  "$fn" >"$T/stdout" 2>&1
  echo "P=$PASS F=$FAIL D=$PEND U=$UNV W=$WARN E=$ERRORS $(cat "$T/extra" 2>/dev/null)"
}

# case_ NAME EXPECT_REGEX FUNCTION
# Output compared: "P=pass F=fail D=pending U=unverified W=advisory E=errors <tnote...>"
case_() {
  local name=$1 expect=$2 fn=$3 out
  # Watchdog: a case that hangs (e.g. waiting on a prompt) fails after CASE_TIMEOUT
  # seconds instead of stalling the run.
  out=$(run_one "$fn" 2>&1 & pid=$!
        perl -e 'sleep shift; kill "TERM", shift' "${CASE_TIMEOUT:-30}" "$pid" >/dev/null 2>&1 & w=$!
        wait "$pid"; kill "$w" 2>/dev/null)
  [ -n "$out" ] || out="TIMEOUT after ${CASE_TIMEOUT:-30}s (hung)"
  if printf '%s' "$out" | grep -Eq -- "$expect"; then
    NPASS=$((NPASS+1)); printf 'ok    %-62s %s\n' "$name" "$out"
  else
    NFAIL=$((NFAIL+1)); FAILED+=("$name"); printf 'FAIL  %-62s got [%s] want /%s/\n' "$name" "$out" "$expect"
  fi
}
skip_case() { NSKIP=$((NSKIP+1)); printf 'skip  %-62s %s\n' "$1" "$2"; }
section() { printf '\n== %s ==\n' "$*"; }

# =============================================================================
section "bundles (v2.3.0: 11-23, 26, 73; review: four contexts, changed content)"
t() { check_bundle "$FIX/aaa.pem" t; };                         case_ "real AAA root = exposure" 'F=1 .*U=0' t
t() { check_bundle "$FIX/emsign-g3.pem" t; };                   case_ "real emSign ECC G3 root = exposure" 'F=1 .*U=0' t
t() { check_bundle "$FIX/emsign-g1.pem" t; };                   case_ "emSign G1 in a general bundle = clean (disclosure site)" 'P=1 F=0 D=0 U=0' t
t() { check_bundle "$TOP/lookalike.pem" t; };                   case_ "same name, different key = review" 'P=0 F=0 D=0 U=1' t
t() { cat "$FIX/emsign-g1.pem" "$FIX/aaa.pem" > m.pem; check_bundle m.pem t; }; case_ "G1 + AAA mixed = exposure" 'F=1 .*U=0' t
t() { cat "$FIX/emsign-g1.pem" > m.pem; printf '\n-----BEGIN CERTIFICATE-----\nbroken\n-----END CERTIFICATE-----\n' >> m.pem; check_bundle m.pem t; }
case_ "good certs + broken block = no verdict" 'P=0 F=0 D=0 U=1' t
t() { cat "$FIX/aaa.pem" > m.pem; printf '\n-----BEGIN CERTIFICATE-----\nbroken\n-----END CERTIFICATE-----\n' >> m.pem; check_bundle m.pem t; }
case_ "AAA + broken block = no verdict" 'F=0 D=0 U=1' t
t() { sed '$d' "$FIX/aaa.pem" > t.pem; check_bundle t.pem t; };   case_ "truncated PEM = no verdict" 'P=0 F=0 D=0 U=1' t
t() { : > e.pem; check_bundle e.pem t; };                         case_ "empty file = no verdict" 'P=0 F=0 D=0 U=1' t
t() { cat "$FIX/emsign-g1.pem" "$TOP/other.key" > m.pem; check_bundle m.pem t; }; case_ "private key block in bundle = no verdict" 'P=0 F=0 D=0 U=1' t
t() { check_bundle "$TOP/aaa.der" t; };                           case_ "DER AAA = exposure" 'F=1 .*U=0' t
t() { sed 's/$/\r/' "$FIX/aaa.pem" > c.pem; check_bundle c.pem t; }; case_ "CRLF PEM = exposure" 'F=1 .*U=0' t
t() { check_bundle "$T/not-there.pem" t; };                       case_ "missing file = no verdict" 'P=0 F=0 D=0 U=1' t
t() { local d='a b "q" $x'; mkdir "$d"; cp "$FIX/aaa.pem" "$d/c d.pem"; check_bundle "$T/$d/c d.pem" t; }
case_ "path with spaces, quotes and \$" 'F=1 .*U=0' t
t() { local f; f=$(printf 'n\nl\tt.pem'); cp "$FIX/aaa.pem" "$f"; check_bundle "$T/$f" t; }; case_ "path with newline/tab" 'F=1 .*U=0|U=1' t
t() { ln -s "$FIX/aaa.pem" al.pem; check_bundle "$FIX/aaa.pem" a; check_bundle al.pem b; check_bundle "$FIX/aaa.pem" c; check_bundle al.pem d; }
case_ "same file x2 + symlink x2 = one finding" 'F=1 .*U=0' t
t() { cp "$FIX/aaa.pem" c1.pem; check_bundle "$FIX/aaa.pem" a; check_bundle c1.pem b; }; case_ "identical copy elsewhere = one finding" 'F=1 .*U=0' t
t() { cp "$FIX/aaa.pem" a.pem; check_bundle a.pem before; cp "$FIX/emsign-g1.pem" a.pem; check_bundle a.pem after; }
case_ "content changed in place = judged again" 'P=1 F=1' t
t() { check_bundle "$FIX/aaa.pem" one note "patched"; check_bundle "$FIX/aaa.pem" two fail; }; case_ "weaker context first cannot hide exposure" 'F=1' t
t() { check_bundle "$FIX/aaa.pem" os pend; check_bundle "$FIX/aaa.pem" var fail; };          case_ "vendor-pending then fixable context = fixable" 'F=1' t

section "certificate directories (v2.3.0: 24, 25)"
t() { mkdir d; check_cert_dir d t; };                                                          case_ "empty directory = not clean" 'P=0 .*U=1' t
t() { mkdir d; cp "$FIX/aaa.pem" d/x.0; cp "$FIX/emsign-g1.pem" d/y.0; check_cert_dir d t; };   case_ "directory with AAA = exposure" 'F=1' t
t() { mkdir d; ln -s "$T/missing" d/hash.0; check_cert_dir d t; };                              case_ "only a broken link = not clean" 'P=0 .*U=1' t
t() { mkdir d; cp "$FIX/emsign-g1.pem" d/a.0; ln -s "$T/missing" d/hash.0; check_cert_dir d t; }; case_ "good cert + broken link = not clean" 'P=0 .*U=1' t
t() { mkdir d; cp "$FIX/emsign-g1.pem" d/a.0; echo junk > d/a.r0; check_cert_dir d t; };        case_ "CRL files ignored" 'P=1 F=0 D=0 U=0' t

section "blocked.certs reader (context only since Oct 24) and JDK file locations"
t() { fullbl bc; tnote "$(bl_missing bc)"; };                                  case_ "16 of 16" ' 0 $' t
t() { fullbl bc; sed -i.b 2d bc; tnote "$(bl_missing bc)"; };                  case_ "15 of 16" ' 1 $' t
t() { printf 'Algorithm=SHA-256\n# eMudhra merged\n' > bc; tnote "$(bl_missing bc)"; }; case_ "marker comment only counts nothing" ' 16 $' t
t() { fullbl bc; sed -i.b 's/SHA-256/SHA-1/' bc; tnote "$(bl_missing bc)"; };  case_ "SHA-1 header = bad format" ' BADFORMAT $' t
t() { fullbl bc; sed -i.b 's/$/\r/' bc; tnote "$(bl_missing bc)"; };           case_ "CRLF blocklist parsed" ' 0 $' t
t() { fullbl bc; echo BAD >> bc; tnote "$(bl_missing bc)"; };                  case_ "garbage line = bad format" ' BADFORMAT $' t
t() { mkdir -p j/lib/security; tnote "$(jdk_blocklist_path "$T/j" | sed "s#$T/j/##")"; };                case_ "JDK 9+ path" ' lib/security/blocked.certs $' t
t() { mkdir -p j/jre/lib/security; tnote "$(jdk_blocklist_path "$T/j" | sed "s#$T/j/##")"; };            case_ "JDK 8 path (jre/)" ' jre/lib/security/blacklisted.certs $' t
t() { mkdir -p j/lib/security; echo 'JAVA_VERSION="1.8.0_511"' > j/release; tnote "$(jdk_blocklist_path "$T/j" | sed "s#$T/j/##")"; }
case_ "standalone JRE 8 path" ' lib/security/blacklisted.certs $' t

section "keytool listing (review: CRLF alias mapping)"
t() { { printf 'Alias name: aaa [jdk]\r\nEntry type: trustedCertEntry\r\n'; sed 's/$/\r/' "$FIX/aaa.pem"; } > listing
      printf '#!/bin/bash\ncat %q\n' "$T/listing" > kt; chmod +x kt; : > store
      tnote "[$(ks_scan "$T/kt" "$T/store" changeit | grep -v @@RC | cut -f1,2,5 | tr '\t' '|' | tr -d '\r')]"; }
case_ "CRLF listing maps alias, strips CR" '\[aaa \[jdk\]\|trustedCertEntry\|ANCHOR\]' t

section "Java: Oracle 2026-10-24 policy (CVE-2026-114820), real keytool"
if [ -z "$KEYTOOL" ]; then
  skip_case "all Java store cases" "no JDK 9+ keytool found (set JAVA_HOME)"
else
  t() { mkjdk "$T/jdk" "${ALL4[@]}" "other [jdk]=$TOP/other.pem"; JAVA_HOME="$T/jdk" audit_java
        tnote "fix=$(printf '%s' "${JDK_FIX[0]:-}" | cut -d'|' -f3 | tr ';' '\n' | sort | paste -sd';' -)"; }
  case_ "all 4 roots in cacerts = exposure, all 4 queued" 'F=1 .*fix=comodoaaaca \[jdk\];emsigneccrootcag3 \[jdk\];emsignrootcag1 \[jdk\];emsignrootcag2 \[jdk\]' t
  t() { mkjdk "$T/jdk" "other [jdk]=$TOP/other.pem"; JAVA_HOME="$T/jdk" audit_java; tnote "queued=${#JDK_FIX[@]}"; }
  case_ "none of the 4 roots = protected" 'P=1 F=0 D=0 U=0 .*queued=0' t
  for r in "comodoaaaca [jdk]=$FIX/aaa.pem" "emsignrootcag1 [jdk]=$FIX/emsign-g1.pem" "emsignrootcag2 [jdk]=$FIX/emsign-g2.pem" "emsigneccrootcag3 [jdk]=$FIX/emsign-g3.pem"; do
    eval "t() { mkjdk \"\$T/jdk\" \"$r\" \"other [jdk]=\$TOP/other.pem\"; JAVA_HOME=\"\$T/jdk\" audit_java; }"
    case_ "only ${r%%=*} = exposure (Oracle removes it)" 'P=0 F=1' t
  done
  t() { mkjdk "$T/jdk" "${ALL4[@]}"; fullbl "$T/jdk/lib/security/blocked.certs"; JAVA_HOME="$T/jdk" audit_java
        grep -q 'has the Oct 21 blocklist' "$T/stdout" && tnote ctx=yes; }
  case_ "complete Oct 21 blocklist + roots = still exposed" 'F=1 .*ctx=yes' t
  t() { mkjdk "$T/jdk" "emsignrootcag1 [jdk]=$TOP/lookalike.pem" "other [jdk]=$TOP/other.pem"; JAVA_HOME="$T/jdk" audit_java; tnote "queued=${#JDK_FIX[@]}"; }
  case_ "root alias name on an unknown key = review, never queued" 'F=0 .*U=1 .*queued=0' t
  t() { LAYOUT8=1 mkjdk "$T/jdk8" "${ALL4[@]}"; JAVA_HOME="$T/jdk8" audit_java; tnote "$(printf '%s' "${JDK_FIX[0]:-}" | cut -d'|' -f2 | sed "s#$T/jdk8/##")"; }
  case_ "JDK 8 layout: jre/lib/security/cacerts" 'F=1 .*jre/lib/security/cacerts' t
  t() { local jh="$HOME/Applications/IntelliJ IDEA.app/Contents/jbr/Contents/Home"; mkjdk "$jh" "${ALL4[@]}"; audit_java; tnote "queued=${#JDK_FIX[@]}"; }
  case_ "IDE-bundled runtime = waiting on vendor, never queued" 'F=0 D=1 .*queued=0' t
  t() { mkjdk "$T/jdk"; printf 'not a keystore\n' > "$T/jdk/lib/security/cacerts"; JAVA_HOME="$T/jdk" audit_java; }
  case_ "unreadable cacerts = no verdict" 'P=0 F=0 .*U=1' t
  t() { mkjdk "$T/jdk" "comodoaaaca [jdk]=$FIX/aaa.pem"; "$KEYTOOL" -delete -keystore "$T/jdk/lib/security/cacerts" -storepass changeit -alias "comodoaaaca [jdk]" >/dev/null 2>&1
        JAVA_HOME="$T/jdk" audit_java; }
  case_ "empty but valid cacerts = trusts nothing (not a read failure)" 'P=1 F=0 D=0 U=0' t
  t() { mkjdk "$T/jdk" "other [jdk]=$TOP/other.pem"; mkjdk "$T/custom" "comodoaaaca=$FIX/aaa.pem"; JAVA_HOME="$T/jdk" audit_java
        check_keystore "$T/jdk/bin/keytool" "$T/custom/lib/security/cacerts" "wrong-password" "custom"; }
  case_ "custom store with the wrong password = no verdict" 'P=1 F=0 .*U=1' t
  t() { mkjdk "$T/jdk" "${ALL4[@]}"; JAVA_TOOL_OPTIONS="-Dcom.sun.net.ssl.checkRevocation=true -Dcom.sun.security.enableCRLDP=true" JAVA_HOME="$T/jdk" audit_java
        grep -q 'revocation checking is on' "$T/stdout" && tnote noted; }
  case_ "revocation flags noted, not counted as the fix" 'F=1 .*noted' t
  t() { mkjdk "$T/jdk" "other [jdk]=$TOP/other.pem"; mkjdk "$T/custom" "comodoaaaca=$FIX/aaa.pem"; mkdir -p "$HOME/.gradle"
        printf "systemProp.javax.net.ssl.trustStore=%s\nsystemProp.javax.net.ssl.trustStorePassword=changeit\n" "$T/custom/lib/security/cacerts" > "$HOME/.gradle/gradle.properties"; JAVA_HOME="$T/jdk" audit_java; }
  case_ "Gradle custom trustStore with AAA = exposure" 'P=1 F=1' t
  t() { mkjdk "$T/jdk" "other [jdk]=$TOP/other.pem"; mkjdk "$T/custom" "other=$TOP/other.pem"; mkdir -p "$HOME/.gradle"
        printf '# systemProp.javax.net.ssl.trustStore=/bad\nsystemProp.javax.net.ssl.trustStore=%s\r\nsystemProp.javax.net.ssl.trustStorePassword=changeit\r\n' "$T/custom/lib/security/cacerts" > "$HOME/.gradle/gradle.properties"; JAVA_HOME="$T/jdk" audit_java; }
  case_ "Gradle custom trustStore clean (CRLF, comment ignored)" 'P=2 F=0' t
  t() { mkdir -p "$HOME/.gradle"; echo "org.gradle.java.home=/not/a/JDK" > "$HOME/.gradle/gradle.properties"; audit_java; }
  case_ "Gradle java.home not a JDK = not proven" 'U=1' t

  section "Java: root removal transaction"
  t() { mkjdk "$T/jdk" "${ALL4[@]}" "other [jdk]=$TOP/other.pem"; local ks="$T/jdk/lib/security/cacerts" h0; h0=$(sha256_of "$ks")
        JAVA_HOME="$T/jdk" audit_java; ROLE=fleet; MODE=remediate; fix_java >/dev/null 2>&1
        tnote "left=[$(aliases_in "$ks")]" "backup=$([ "$(sha256_of "$ks".emsign-bak-*)" = "$h0" ] && echo verified || echo bad)" "stray=$(ls -A "$T/jdk/lib/security" | grep -c '^\.cacerts')"
        ROLE=dev; PASS=0; FAIL=0; SEEN=""; JDK_FIX=(); JAVA_HOME="$T/jdk" audit_java; tnote "reaudit=P$PASS/F$FAIL"; }
  case_ "remediate: 4 roots removed, other kept, backup verified, re-audit clean" 'left=\[other \[jdk\]\] backup=verified stray=0 reaudit=P1/F0' t
  t() { mkjdk "$T/jdk" "${ALL4[@]}"; local ks="$T/jdk/lib/security/cacerts" h0; h0=$(sha256_of "$ks")
        JAVA_HOME="$T/jdk" audit_java; ROLE=fleet; MODE=audit; run_fixes >/dev/null 2>&1
        tnote "unchanged=$([ "$(sha256_of "$ks")" = "$h0" ] && echo yes || echo no)" "actions=${#ACTIONS[@]}"; }
  case_ "fleet audit: nothing changed, action recorded" 'unchanged=yes actions=1' t
  t() { mkjdk "$T/jdk" "${ALL4[@]}"; local ks="$T/jdk/lib/security/cacerts" h0; h0=$(sha256_of "$ks")
        # Through run_pass, the real entry point: without --yes and with stdin not a
        # terminal it must stop after the audit and never prompt.
        ROLE=dev; MODE=interactive; YES=0; JAVA_HOME="$T/jdk" run_pass </dev/null >/dev/null 2>&1
        tnote "unchanged=$([ "$(sha256_of "$ks")" = "$h0" ] && echo yes || echo no)" "fixed=$FIXED"; }
  case_ "developer, no --yes, no terminal: nothing changed" 'unchanged=yes fixed=0' t
  t() { mkjdk "$T/jdk" "${ALL4[@]}" "other [jdk]=$TOP/other.pem"; JAVA_HOME="$T/jdk" audit_java; YES=1; MODE=interactive; fix_java >/dev/null 2>&1
        tnote "left=[$(aliases_in "$T/jdk/lib/security/cacerts")]"; }
  case_ "developer --yes: roots removed" 'left=\[other \[jdk\]\]' t
  # Another writer touches the live store while the copy is being edited.
  t() { mkjdk "$T/jdk" "${ALL4[@]}"; local ks="$T/jdk/lib/security/cacerts" h1
        printf '#!/bin/bash\ncase " $* " in *" -delete "*) printf x >> %q ;; esac\nexec %q "$@"\n' "$ks" "$KEYTOOL" > "$T/jdk/bin/keytool.w"
        chmod +x "$T/jdk/bin/keytool.w"; JAVA_HOME="$T/jdk" audit_java; mv -f "$T/jdk/bin/keytool.w" "$T/jdk/bin/keytool"
        h1=$(sha256_of "$ks"); ROLE=fleet; MODE=remediate; fix_java >/dev/null 2>&1
        grep -q 'changed while the fix was staged' <(printf '%s\n' "${RESULTS[@]}") && tnote refused
        tnote "stray=$(ls -A "$T/jdk/lib/security" | grep -c '^\.cacerts')"; }
  case_ "live store changed mid-fix: refused, not overwritten" 'E=1 refused stray=0' t
  t() { mkjdk "$T/jdk" "${ALL4[@]}"; local ks="$T/jdk/lib/security/cacerts" h0; h0=$(sha256_of "$ks")
        printf '#!/bin/bash\ncase " $* " in *" -delete "*) exit 1 ;; esac\nexec %q "$@"\n' "$KEYTOOL" > "$T/kt.w"; chmod +x "$T/kt.w"
        JAVA_HOME="$T/jdk" audit_java; ln -sf "$T/kt.w" "$T/jdk/bin/keytool"; ROLE=fleet; MODE=remediate; fix_java >/dev/null 2>&1
        tnote "unchanged=$([ "$(sha256_of "$ks")" = "$h0" ] && echo yes || echo no)" "stray=$(ls -A "$T/jdk/lib/security" | grep -c '^\.cacerts')"; }
  case_ "keytool delete fails: live store unchanged, no leftovers" 'E=1 unchanged=yes stray=0' t
fi

section "cross-signed path (v2.3.0 CrossSignedPathTests): why AAA must go too"
X=$TOP/xs; mkdir -p "$X"
( cd "$X" || exit
  printf 'basicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n' > root.ext
  printf 'basicConstraints=critical,CA:true,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n' > int.ext
  printf 'basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:synthetic.invalid\n' > leaf.ext
  for r in A B; do
    openssl req -x509 -newkey rsa:2048 -nodes -keyout root$r.key -subj "/CN=Synthetic Root $r" -days 2 -sha256 -addext basicConstraints=critical,CA:true -addext keyUsage=critical,keyCertSign,cRLSign -out root$r.pem
  done
  openssl req -new -newkey rsa:2048 -nodes -keyout int.key -subj "/CN=Same Intermediate Key" -out int.csr
  n=20; for r in A B; do n=$((n+1)); openssl x509 -req -in int.csr -CA root$r.pem -CAkey root$r.key -set_serial $n -days 2 -sha256 -extfile int.ext -out int$r.pem; done
  openssl req -new -newkey rsa:2048 -nodes -keyout leaf.key -subj "/CN=synthetic.invalid" -out leaf.csr
  openssl x509 -req -in leaf.csr -CA intA.pem -CAkey int.key -set_serial 30 -days 2 -sha256 -extfile leaf.ext -out leaf.pem
) >/dev/null 2>&1
xv() { openssl verify -purpose sslserver -CAfile "$1" -untrusted "$X/$2" "$X/leaf.pem" >/dev/null 2>&1; }
if xv "$X/rootA.pem" intA.pem; then NPASS=$((NPASS+1)); echo "ok    primary chain verifies (positive control)"
else NFAIL=$((NFAIL+1)); FAILED+=("cross-sign positive control"); echo "FAIL  primary chain should verify"; fi
if xv "$X/rootB.pem" intB.pem; then NPASS=$((NPASS+1)); echo "ok    primary root removed: the cross-signed path still verifies"
else NFAIL=$((NFAIL+1)); FAILED+=("cross-sign alternate path"); echo "FAIL  cross-signed path should still verify"; fi
if ! xv "$FIX/emsign-g1.pem" intA.pem && ! xv "$FIX/emsign-g1.pem" intB.pem; then NPASS=$((NPASS+1)); echo "ok    both roots removed: neither path verifies"
else NFAIL=$((NFAIL+1)); FAILED+=("cross-sign both removed"); echo "FAIL  no path should verify without either root"; fi

section "macOS /etc/ssl/cert.pem (Apple fix pending) and Ruby"
mkruby() { mkdir -p "$HOME/bin"; printf '#!/bin/bash\ncase "$*" in *DEFAULT_CERT_FILE*) printf %%s %q ;; *RUBY_VERSION*) printf 2.6.10 ;; esac\n' "$1" > "$HOME/bin/ruby"; chmod +x "$HOME/bin/ruby"; }
export -f mkruby
t() { cp "$FIX/aaa.pem" sys.pem; MACOS_CERT_PEM="$T/sys.pem"; ln -s "$T/sys.pem" link.pem; mkruby "$T/link.pem"; PATH="$HOME/bin:$PATH" audit_other; }
case_ "system Ruby on Apple's bundle = waiting on Apple, not fix-now" 'F=0 D=1' t
t() { cp "$FIX/aaa.pem" sys.pem; MACOS_CERT_PEM="$T/sys.pem"; audit_macos; mkruby "$T/sys.pem"; PATH="$HOME/bin:$PATH" audit_other; }
case_ "macOS check + system Ruby = one vendor item, no fail" 'F=0 D=1' t
t() { cp "$FIX/aaa.pem" own.pem; MACOS_CERT_PEM="$T/none.pem"; mkruby "$T/own.pem"; PATH="$HOME/bin:$PATH" audit_other; }
case_ "Ruby with its own bundle containing AAA = exposure" 'F=1 D=0' t

section "environment and shell files (bypasses, GIT_SSL_NO_VERIFY=false, PIP_TRUSTED_HOST)"
t() { NODE_TLS_REJECT_UNAUTHORIZED=0 audit_env; };       case_ "NODE_TLS_REJECT_UNAUTHORIZED=0 = exposure" 'F=1' t
t() { GIT_SSL_NO_VERIFY=false audit_env; };              case_ "GIT_SSL_NO_VERIFY=false = fine" 'F=0' t
t() { GIT_SSL_NO_VERIFY=1 audit_env; };                  case_ "GIT_SSL_NO_VERIFY=1 = exposure" 'F=1' t
t() { PIP_TRUSTED_HOST=pypi.org audit_env; };            case_ "PIP_TRUSTED_HOST = exposure" 'F=1' t
t() { printf '# export NODE_TLS_REJECT_UNAUTHORIZED=0\n  # GIT_SSL_NO_VERIFY=1\n' > "$HOME/.zshrc"; audit_env; }; case_ "commented bypass in .zshrc ignored" 'F=0' t
t() { printf 'export NODE_TLS_REJECT_UNAUTHORIZED=0\nexport GIT_SSL_NO_VERIFY=true\n' > "$HOME/.zshrc"; audit_env; }; case_ "active bypasses in .zshrc = exposure" 'F=2' t
t() { SSL_CERT_FILE="$FIX/aaa.pem" audit_env; };         case_ "SSL_CERT_FILE -> AAA bundle = exposure" 'F=1' t

section "Node (review: patched lines + extra AAA, old/EOL, NODE_OPTIONS never replayed)"
mknode() { mkdir -p "$HOME/.nvm/versions/node/v$1/bin"
  printf '#!/bin/bash\n[ -n "${NODE_OPTIONS:-}" ] && touch %q\n[ "$1" = --version ] && echo v%s\n' "$T/replayed" "$1" > "$HOME/.nvm/versions/node/v$1/bin/node"
  chmod +x "$HOME/.nvm/versions/node/v$1/bin/node"; }
export -f mknode
t() { npm() { :; }; mknode 22.23.4; mknode 24.22.1; mknode 26.12.1; NODE_EXTRA_CA_CERTS="$FIX/aaa.pem" audit_node; }
case_ "22.23.4 / 24.22.1 / 26.12.1 + extra AAA = clean" 'P=3 F=0 D=0 U=0' t
t() { npm() { :; }; mknode 22.23.3; audit_node; };        case_ "22.23.3 = exposure" 'P=0 F=1' t
t() { npm() { :; }; mknode 20.19.0; audit_node; };        case_ "20.19.0 (end of life) = exposure" 'P=0 F=1' t
t() { npm() { :; }; mknode 22.23.3; NODE_EXTRA_CA_CERTS="$FIX/aaa.pem" audit_node; }; case_ "unpatched + extra AAA = 2 exposures" 'F=2' t
t() { npm() { :; }; mknode 24.22.1; NODE_OPTIONS="--require $T/evil.js" audit_node; tnote "replayed=$([ -e "$T/replayed" ] && echo yes || echo no)"; }
case_ "NODE_OPTIONS loader never replayed" 'P=1 .*replayed=no' t
t() { printf 'strict-ssl=false\n' > "$HOME/.npmrc"; audit_node; };                case_ ".npmrc strict-ssl=false = exposure" 'F=1' t
t() { printf 'cafile=%s\n' "$FIX/aaa.pem" > "$HOME/.npmrc"; audit_node; };      case_ ".npmrc cafile -> AAA = exposure" 'F=1' t

section "Go (v2.3.0: 41-49 thresholds, prerelease, binaries never executed)"
mkgo() { mkdir -p "$HOME/sdk/go$1/bin"; printf '#!/bin/bash\n[ "$1 $2" = "env GOVERSION" ] && echo go%s\n' "$1" > "$HOME/sdk/go$1/bin/go"; chmod +x "$HOME/sdk/go$1/bin/go"; }
export -f mkgo
for gv in 1.26.9:F=1 1.26.10:P=1 1.27.2:F=1 1.27.3:P=1 1.25.12:F=1 1.28.0:P=1; do
  eval "t() { audit_go_bins() { :; }; mkgo ${gv%%:*}; audit_go; }"; case_ "go${gv%%:*}" "${gv#*:}" t
done
t() { audit_go_bins() { :; }; mkgo 1.27.3rc1; audit_go; };  case_ "go1.27.3rc1 (prerelease) = not proven" 'P=0 F=0 D=0 U=1' t
t() { audit_go_bins() { :; }; mkgo devel; audit_go; };      case_ "go devel = not proven" 'P=0 F=0 D=0 U=1' t
t() { mkdir -p "$HOME/go/bin"; printf '#!/bin/bash\ntouch %q\n# go1.26.3\n' "$T/ran" > "$HOME/go/bin/tool"; chmod +x "$HOME/go/bin/tool"
      audit_go_bins; tnote "ran=$([ -e "$T/ran" ] && echo yes || echo no)"; }
case_ "old Go binary flagged, never executed" 'W=1 .*ran=no' t
t() { mkdir -p "$HOME/go/bin"; printf '#!/bin/bash\nexit 0\n' > "$HOME/go/bin/tool"; chmod +x "$HOME/go/bin/tool"; audit_go_bins; }
case_ "Go binary without readable version = advisory" 'W=1' t

section "Gradle properties (review: comments, CRLF, spaces)"
t() { printf '# systemProp.javax.net.ssl.trustStore=/bad\n  ! org.gradle.java.home=/missing\norg.gradle.jvmargs=-Xmx2g\n' > g
      tnote "<$(props_value g org.gradle.java.home)$(props_value g systemProp.javax.net.ssl.trustStore)>"; }
case_ "comments ignored" ' <> $' t
t() { printf 'org.gradle.java.home = JDK home/x\r\n' > g; tnote "<$(props_value g org.gradle.java.home)>"; }; case_ "CRLF value with spaces" '<JDK home/x>' t

section "Python (one interpreter reached by two paths is inspected once)"
t() { xcode-select() { return 0; }; mkdir -p r "$HOME/.pyenv/versions/a/bin" "$HOME/.pyenv/versions/b/bin"
      printf '#!/bin/bash\ncase "$2" in -V) echo Python 3.13.1;; -c) echo "cafile|%s";; esac\n' "$FIX/emsign-g1.pem" > r/python3; chmod +x r/python3
      ln -s "$T/r/python3" "$HOME/.pyenv/versions/a/bin/python3"; ln -s "$T/r/python3" "$HOME/.pyenv/versions/b/bin/python3"
      PATH=/usr/bin:/bin audit_python; }
case_ "shared python binary = inspected once" 'P=1 F=0' t

section "result and exit contract (v2.3.0: warnings never fail, nothing hides exposure)"
t() { WARN=2; tnote "$(dev_status):$(status_rc "$(dev_status)")"; };           case_ "advisories only = PROTECTED, exit 0" 'PROTECTED:0' t
t() { WARN=1; FAIL=1; tnote "$(dev_status):$(status_rc "$(dev_status)")"; };   case_ "advisory + exposure = EXPOSED, exit 2" 'EXPOSED:2' t
t() { PEND=1; tnote "$(dev_status):$(status_rc "$(dev_status)")"; };           case_ "vendor only = VENDOR_PENDING, exit 1" 'VENDOR_PENDING:1' t
t() { PEND=1; UNV=1; tnote "$(dev_status):$(status_rc "$(dev_status)")"; };    case_ "unverified outranks vendor, exit 3" 'UNVERIFIED:3' t
t() { ERRORS=1; tnote "$(dev_status):$(status_rc "$(dev_status)")"; };         case_ "fix error alone = UNVERIFIED" 'UNVERIFIED:3' t
t() { ERRORS=1; FAIL=1; tnote "$(dev_status):$(status_rc "$(dev_status)")"; }; case_ "fix error cannot hide exposure" 'EXPOSED:2' t

section "command line and loading"
t() { bash "$S" --bogus >/dev/null 2>&1; tnote "rc=$?"; };              case_ "unknown option rejected" 'rc=2' t
t() { bash "$S" --remove-roots >/dev/null 2>&1; tnote "rc=$?"; };       case_ "retired --remove-roots rejected" 'rc=2' t
t() { bash "$S" --blocked-url=x >/dev/null 2>&1; tnote "rc=$?"; };      case_ "retired --blocked-url rejected" 'rc=2' t
t() { bash "$S" --help >/dev/null 2>&1; tnote "rc=$?"; };               case_ "--help exits 0" 'rc=0' t
t() { bash -n "$S"; tnote "rc=$?"; };                                   case_ "syntax" 'rc=0' t
t() { tnote "out=$(bash -c 'source "$1" / host user remediate; echo "role=$ROLE"' _ "$S" 2>&1 | tr '\n' ' ')"; }
case_ "sourcing with Jamf-style arguments starts nothing" 'out=role=dev *$' t

printf '\nRESULT: %d passed, %d failed, %d skipped\n' "$NPASS" "$NFAIL" "$NSKIP"
for f in ${FAILED[@]+"${FAILED[@]}"}; do echo "  failed: $f"; done
[ "$NFAIL" -eq 0 ]
