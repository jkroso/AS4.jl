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

## Tests

```sh
julia --project=. test/runtests.jl     # everything
julia --project=. test/xmlsig.jl       # one layer
```

Gated extras: `AS4_LIVE=1` enables the live EVTE STS smoke; xmlsec1/WSS4J
oracle tests skip when the tools aren't installed.
