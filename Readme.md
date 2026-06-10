# AS4.jl

Julia client for ebMS 3.0 / AS4 messaging, profiled for the ATO's SBR2 channel
(BAS, STP, CTR lodgment). Client-only: pushes requests, pulls responses — no
inbound HTTP endpoint required.

Layers:

- `XMLSig.jl` — Exclusive C14N (libxml2) + XML-DSig sign/verify (libcrypto), incl. the WS-Security SwA attachment transform
- `Keystore.jl` — ABR machine-credential `keystore.xml` (cert + encrypted PKCS#8 key)
- `WSTrust.jl` — WS-Trust 1.3 client for the ATO MAS-ST security token service
- `MIME.jl` — `multipart/related` writer + parser
- `ebMS3.jl` — SOAP 1.2 envelope, `eb:Messaging`, push / selective-pull / sync MEPs
- `SBR.jl` — ATO endpoints, header conventions, per-service builders (PAYEVNT, AS)

Design spec and primary-source research live in the Centient repo:
`docs/superpowers/specs/2026-06-11-as4-library-design.md`, `docs/research/sbr2/`.

## Usage sketch

```julia
@use "github.com/jkroso/AS4.jl" load lodge collect_response payevnt_message Env

cred = load("~/.centient/keystore.xml", password)        # ABR machine credential
msg = payevnt_message(payevnt_xml; abn="12 345 678 901",
                      product_id=SBR_PRODUCT_ID, bms=("Centient","Centient","1.0"))
receipt = lodge(Env.EVTE, cred, msg)                     # STS token → signed push → Receipt
resp = collect_response(Env.EVTE, cred, msg.message_id)  # nothing = poll again later
```

## Tests

```sh
julia --project=. test/runtests.jl     # everything
julia --project=. test/xmlsig.jl       # one layer
```

Gated extras: `AS4_LIVE=1` enables the live EVTE STS smoke; the xmlsec1 oracle
test skips when the tool isn't installed.

## Verification status (2026-06-11)

| Claim | Evidence |
|---|---|
| Exclusive C14N correct (incl. PrefixList, WithComments) | W3C merlin interop vectors, byte-exact digests |
| XML-DSig sign/verify interoperable | aleksey rsa-sha256 vector verifies; our signatures verify in xmlsec1 (independent C stack) |
| Verifier accepts real third-party AS4 stacks | signed captures from Governikus + helger APs verify |
| ABR machine-credential keystore decrypts | official ATO public EVTE keystore (real, expired) loads + signs |
| WS-Trust RST accepted by the real ATO STS | **live EVTE exchange**: STS parsed the envelope and reached certificate-path validation (E2169 — the test credential expired 2024). Token issuance pending a current credential. |
| MEP behaviour (push/receipt, empty-MPC pull, MessageId-stable retry) | mock-peer tests |
| SwA attachment signing | self-verify + structure; WSS4J oracle written but **unrun** (no JVM here) |
| EVTE end-to-end lodgment | **pending DSP registration** (test credential + endpoint access) |

AS.0004 Service/Action URIs are convention-derived — verify against the AS MIG
before the first EVTE run (marked TODO in `SBR.jl`).
