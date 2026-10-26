# Public certificate fixtures

Public certificates only (no private keys). They are test inputs, not a trust bundle.

| File | Subject | Cert SHA-256 | SPKI SHA-256 (what the script matches) | Source |
|---|---|---|---|---|
| aaa.pem | AAA Certificate Services (Comodo/Sectigo) | D7A7A0FB…EA699EF4 | BD153ED7B0434F6886B17BCE8BBE84ED340C7132D702A8F4FA318F756ECBD6F3 | v2.3.0 suite (Mozilla ca-certificates) |
| emsign-g1.pem | emSign Root CA - G1 | 40F6AF03…C8D00367 | 376A1A7082A593DCCC20D561D119E9AB8D30F11CC321D0A37FA41F0DF284E01C | v2.3.0 suite (Mozilla ca-certificates) |
| emsign-g2.pem | emSign Root CA - G2 | 1AA0C270…F24F3AF3 | 71F8ADEEC2B58ADBDF6205C98DDE928A4254B03695193D7F9A63A9A2588095D0 | OpenJDK `src/java.base/share/data/cacerts/emsignrootcag2` (jdk-25+36) |
| emsign-g3.pem | emSign ECC Root CA - G3 | 86A1ECBA…A36BBE6B | 8D417DB2DD8BF5E3084D1E3F196D583849D81BDD4C00C70B9D39369E96B8C782 | v2.3.0 suite (Mozilla ca-certificates) |

How the tests use them:

- **General bundles** (certifi, Homebrew, `SSL_CERT_FILE`…) follow the disclosure site: AAA and ECC G3 are affected anchors; G1 is clean.
- **Java trust stores** follow Oracle's 2026-10-24 guidance (CVE-2026-114820): all four of these roots must be gone from `cacerts` (`comodoaaaca`, `emsignrootcag1`, `emsignrootcag2`, `emsigneccrootcag3`).

Synthetic look-alikes (same name, different key), the cross-signed chain, and the private keys behind them are generated in temporary directories during a test run and never shipped.

## trust-settings-system.txt

Real `security dump-trust-settings -s | grep -B3 -A10 -Ei 'emsign|AAA Certificate'` output from a developer Mac (2026-10-26). It is Apple's built-in root list: every shipped root shows "Number of trust settings : 0". The tests use it to prove the script does not treat that list as an override.
