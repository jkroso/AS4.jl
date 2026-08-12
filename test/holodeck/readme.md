# Holodeck B2B loopback peer

Live push interop against an independent open-source AS4 server
([Holodeck B2B](https://github.com/holodeck-b2b/Holodeck-B2B) 8.1.1).

Cross-stack evidence that does **not** need Holodeck:

| Evidence | Where |
|---|---|
| Governikus + helger signed captures verify | `test/interop.jl` |
| xmlsec1 oracle on our envelopes | `test/xmlsig.jl`, `test/ebms3.jl` |
| WSS4J multipart oracle | `test/oracle_wss4j.jl` (needs jbang + JDK) |
| Live ATO EVTE STS | `test/wstrust.jl` with `AS4_LIVE=1` |

## Prerequisites

- OpenJDK (`brew install openjdk`) with `JAVA_HOME` set (see `~/.zshrc`)
- `curl`, `unzip`, `keytool` (from the JDK)

## Install / start / stop

```sh
cd test/holodeck
./setup.sh          # download ~47 MB zip, certs, P-Modes (once)
./start.sh          # listens on :8080
./stop.sh
```

The distribution lives under `hb2b/` and is gitignored. Re-run `setup.sh`
after a clean checkout.

AS4 endpoint: `http://127.0.0.1:8080/holodeckb2b/as4`  
Log: `holodeck.log` · delivered payloads: `hb2b/data/msg_in/`

## Automated test

```sh
./start.sh
julia --project=. test/holodeck_live.jl   # or: test/runtests.jl
```

| Env | Behaviour |
|---|---|
| (default) | Skip if nothing is listening on `:8080` |
| `AS4_HOLODECK=1` | Require Holodeck — fail if the peer is down |
| `AS4_HOLODECK_URL=…` | Override the AS4 endpoint (default `http://127.0.0.1:8080/holodeckb2b/as4`) |

When the peer is up the test signs a push, asserts a `Receipt` (and NRI digests
when present), and checks that a delivery file appears under `hb2b/data/msg_in/`.

## Manual smoke (same traffic as the test)

```julia
@use "./ebMS3.jl" UserMessage Part push Receipt
@use "./XMLSig.jl" load_pem_keypair

pair = load_pem_keypair("test/fixtures/key.pem", "test/fixtures/cert.pem")
msg = UserMessage(
  from=("org:as4jl", "urn:oasis:names:tc:ebcore:partyid-type:unregistered",
        "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/initiator"),
  to=("org:holodeck", "urn:oasis:names:tc:ebcore:partyid-type:unregistered",
      "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/responder"),
  service="urn:test", action="Deliver",
  parts=[Part(Vector{UInt8}("<doc/>"); name="DOC", doctype="BASE")])
r = push("http://127.0.0.1:8080/holodeckb2b/as4", msg; cred=pair)
@assert r isa Receipt
```

## What setup installs

| Piece | Role |
|---|---|
| Holodeck B2B 8.1.1 distribution | MSH on port 8080 |
| Example keystores (`secrets` / `nosecrets` / `trusted`) | Default Holodeck crypto material |
| `as4jl` entry in partner + trusted stores | Fixture `cert.pem` so Holodeck trusts our signatures |
| `as4jl-push-resp.xml` P-Mode | One-way push, sync Receipt, parties `org:as4jl` → `org:holodeck` |
| `ex-pm-push-resp.xml` | Stock Holodeck example receive P-Mode |

Default keystore passwords are Holodeck’s sample values (`secrets` / `nosecrets` /
`trusted`) — fine for a local loopback, not for production.
