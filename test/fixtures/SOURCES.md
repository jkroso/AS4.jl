# Fixture provenance

| File | Source |
|---|---|
| `w3c/exc-signature.xml` | github.com/lsh123/xmlsec `tests/merlin-exc-c14n-one/` (W3C Exclusive C14N interop, Merlin Hughes) |
| `w3c/enveloping-sha256-rsa-sha256.xml` | github.com/lsh123/xmlsec `tests/aleksey-xmldsig-01/` |
| `phase4/dump-raw.as4out` | github.com/phax/phase4 `phase4-peppol-client/src/test/resources/` — full outbound AS4 MIME capture |
| `phase4/helger.as4in`, `phase4/governikus.as4in` | same repo, `external/verify/` — real signed responses from independent AS4 stacks |
| `phase4/UserMessage12.xml`, `UserMessageWithCompressedPayload12.xml`, `PullRequest12.xml` | same repo, `phase4-lib/src/test/resources/external/soap12test/` |
| `keystore-usi.xml` | github.com/ato-pub/usi.cl.java `keystore/` — official ATO public EVTE machine credentials (password `Password1!`, certs expired 2024, fine for parse/decrypt tests) |
| `key.pem`, `cert.pem` | generated self-signed test keypair (10y) |
