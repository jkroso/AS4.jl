# Holodeck B2B loopback peer (manual)

Live push interop against an independent open-source AS4 server. Still a
**manual** recipe — Holodeck wants a container and a P-Mode tailored to the
fixture cert, which is outside the default test suite. Cross-stack evidence
that *is* automated:

| Evidence | Where |
|---|---|
| Governikus + helger signed captures verify | `test/interop.jl` |
| xmlsec1 oracle on our envelopes | `test/xmlsig.jl`, `test/ebms3.jl` (when `xmlsec1` is on PATH) |
| WSS4J multipart oracle | `test/oracle_wss4j.jl` (when `jbang` is installed) |
| Live ATO EVTE STS | `test/wstrust.jl` with `AS4_LIVE=1` |

Holodeck remains the only full **live peer MSH** check; run it when you need
push/receipt against something that is not the ATO.

## Recipe

1. Build an image over the Holodeck B2B distribution (no official image):

```dockerfile
FROM eclipse-temurin:17-jre
ADD https://github.com/holodeck-b2b/Holodeck-B2B/releases/download/8.1.1/holodeck-b2b-8.1.1.zip /tmp/
RUN cd /opt && unzip /tmp/holodeck-b2b-8.1.1.zip && mv holodeck-b2b-8.1.1 hb2b
EXPOSE 8080
CMD ["/opt/hb2b/bin/startServer.sh"]
```

2. Drop a receive P-Mode (from the distribution's `examples/pmodes/ex-pm-push-resp.xml`,
   party/security adjusted to `test/fixtures/cert.pem`) into `repository/pmodes/`.

3. Push at it from Julia and assert the receipt + delivered file:

```julia
@use "../../ebMS3.jl" UserMessage Part push Receipt
@use "../../XMLSig.jl" load_pem_keypair
pair = load_pem_keypair("test/fixtures/key.pem", "test/fixtures/cert.pem")
msg = UserMessage(from=("org:example","urn:oasis:names:tc:ebcore:partyid-type:unregistered","Sender"),
                  to=("org:holodeck","urn:oasis:names:tc:ebcore:partyid-type:unregistered","Receiver"),
                  service="urn:test", action="Deliver",
                  parts=[Part(Vector{UInt8}("<doc/>"))])
r = push("http://localhost:8080/holodeckb2b/as4", msg; cred=pair)
@assert r isa Receipt
# then check data/msg_in inside the container for the delivered payload
```
