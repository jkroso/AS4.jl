# AS4.jl

A Julia client for ebMS 3.0 / AS4 — the protocol you must speak if you want to
lodge BAS, STP, or company tax returns directly with the Australian Taxation
Office's SBR2 channel.

AS4 is what happens when a government is asked to send a file over the
internet and answers with a committee. A business document may not simply be
POSTed; it must be gzipped into a MIME part, strapped to a SOAP 1.2 envelope,
described in an ebMS header, vouched for by a SAML assertion that you fetch
from a separate token service via WS-Trust (signing *that* request too), and
then signed — four times over, with XML canonicalization rules so delicate
that two correct implementations can disagree about whitespace. The result is
byte-for-byte reproducible XML, a phrase that should never have needed to
exist. Every layer is an OASIS standard from the mid-2000s, and every layer is
load-bearing. This library exists so nothing else in the stack has to know any
of that.

To be fair to the ATO: having buried the treasure, they published the map —
the wire format is thoroughly documented, the test STS is open, and their own
reference keystores are on GitHub. Credit where due. The protocol still has a
MIME boundary inside a SOAP envelope inside a signature inside a token dance,
but at least it's *documented* bureaucracy.

## A brief history of sending a file

- **1996 — AS1.** The IETF asks: what if EDI documents, but over email? Signed,
  encrypted business documents delivered via SMTP, with a signed receipt mailed
  back. A complete success, except that it was email, so nobody could say with
  confidence whether anything had arrived, including the receipts.

- **2002 — AS2.** What if the same thing, but over HTTP? This one actually
  worked, so naturally Walmart made it mandatory for every supplier on Earth,
  and twenty-three years later it still moves a terrifying share of global
  retail. The lesson — *keep it simple and ship it* — was duly recorded and
  never consulted again.

- **2007 — AS3.** What if the same thing, but over FTP? No one had asked, and
  no one answered. AS3 is survived by its specification.

- **Meanwhile, in a parallel universe — ebXML.** The UN and OASIS had spent the
  same years designing ebMS, a messaging framework with every capability a
  committee could vote for: SOAP envelopes, P-Modes, message partition
  channels, pull semantics, reliability modules. ebMS 2.0 was so thorough that
  implementing it became a career. ebMS 3.0 (2007) was the apology.

- **2013 — AS4.** The grand synthesis: take AS2's "just enough" philosophy and
  re-express it as a *conformance profile* of ebMS 3.0 — thereby achieving the
  simplicity of AS2 by way of SOAP 1.2, WS-Security 1.1, XML Signature,
  Exclusive Canonicalization, SOAP-with-Attachments, and a 90-page profile
  document narrowing a larger document. It was promptly blessed as ISO 15000-2
  and adopted by the EU for eDelivery, by Peppol for e-invoicing, and by the
  Australian government for tax — the rare technology whose entire user base is
  jurisdictions.

- **2017 — Australia.** The ATO, selecting a transport for Standard Business
  Reporting, looked upon AS4 — push *and* pull, four signatures per message, a
  SAML token minted fresh every thirty minutes by a second web service — and
  felt seen. They adopted it, then added two extensions the AS4 profile had
  deliberately left out, restoring some of the complexity OASIS had worked so
  hard to remove.

- **2026 — the filter fails.** Whatever else may be said of the stack, it
  served one purpose with quiet distinction: nobody could lodge anything
  without first reading several hundred pages of OASIS prose, which kept the
  riff-raff away from the endpoints more effectively than the signatures ever
  did. Then language models learned to read specification documents, and this
  library was written in a day, supervised by a man who has read none of the
  works cited above. The moat is dry. Everyone's in.

This library implements the 2017 layer of that archaeology, by way of the
2026 incident.

## Layers

| File | Job |
|---|---|
| `XMLSig.jl` | Exclusive C14N (libxml2) + XML-DSig sign/verify, incl. the WS-Security SwA attachment transform |
| `Keystore.jl` | ABR machine-credential `keystore.xml` — cert chain + encrypted PKCS#8 key |
| `WSTrust.jl` | WS-Trust 1.3 client for the ATO MAS-ST security token service |
| `MIME.jl` | `multipart/related` writer + parser |
| `ebMS3.jl` | SOAP envelope, `eb:Messaging`, WS-Security header, push / selective-pull / sync MEPs |
| `SBR.jl` | ATO endpoints, header conventions, per-service builders (PAYEVNT, AS) |

Client-only, light-client style: it initiates every exchange and never needs an
inbound HTTP endpoint. No XML Encryption (the ATO profile doesn't use it
client-side — TLS 1.3 carries confidentiality). Peppol e-invoicing could layer
on the same core later.

## Usage

```julia
@use "github.com/jkroso/AS4.jl" load lodge collect_response payevnt_message Env

cred = load("keystore.xml", password)                    # ABR machine credential
msg = payevnt_message(payevnt_xml; abn="12 345 678 901",
                      product_id=SBR_PRODUCT_ID, bms=("Example","Example","1.0"))
receipt = lodge(Env.EVTE, cred, msg)                     # STS token → signed push → Receipt
resp = collect_response(Env.EVTE, cred, msg.message_id)  # nothing = poll again later
```

Lower layers (`c14n`, `sign!`, `verify`, `issue_token`, `push`/`pull`/`sync_call`)
are importable individually.

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
| Verifier accepts real third-party AS4 stacks | signed captures from Governikus + helger access points verify |
| ABR machine-credential keystore decrypts | official ATO public EVTE keystore (real, expired) loads + signs |
| WS-Trust RST accepted by the real ATO STS | **live EVTE exchange**: the STS parsed our envelope and reached certificate-path validation, objecting only that the public test credential expired in 2024 (E2169). Token issuance pending a current credential. |
| MEP behaviour (push/receipt, empty-MPC pull, MessageId-stable retry) | mock-peer tests |
| SwA attachment signing | self-verify + structure; WSS4J oracle written but unrun (no JVM here) |
| EVTE end-to-end lodgment | pending DSP registration (test credential + endpoint access) |

AS.0004 Service/Action URIs are convention-derived — verify against the AS MIG
before the first EVTE run (marked TODO in `SBR.jl`).

## References

- [SBR ebMS3 Web services Implementation Guide](https://www.sbr.gov.au/sbr-ebms3-webservices-artefacts) — the load-bearing document
- [OASIS AS4 profile of ebMS 3.0](https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/profiles/AS4-profile/v1.0/os/AS4-profile-v1.0-os.html)
- [WSS 1.1 SwA Profile](https://docs.oasis-open.org/wss/v1.1/wss-v1.1-spec-os-SwAProfile.pdf) — attachment signing
- [ato-pub/usi.cl.java](https://github.com/ato-pub/usi.cl.java) — official ATO reference client for the STS leg (and source of the public test keystore)
- Fixture provenance: `test/fixtures/SOURCES.md`
