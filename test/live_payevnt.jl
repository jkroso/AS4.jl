#=
Live EVTE PAYEVNT submit — run manually, never in CI:

  AS4_KEYSTORE=/path/to/evte.keystore.xml \
  AS4_PASSWORD=… \
  AS4_PRODUCT_ID=… \
  AS4_BMS_VENDOR=… AS4_BMS_NAME=… [AS4_BMS_VERSION=1.0] \
  AS4_SUITE=/path/to/payevnt-suite/inner \
  julia --project=. test/live_payevnt.jl

Pushes conformance scenario BULK-001 (PAYEVNT + 3× PAYEVNTEMP) to the EVTE
bulk channel as the matching test entity (YALACT129), then selective-pulls
for the business response. AS4_PRODUCT_ID is the ATO-allocated EVTE product
ID; AS4_BMS_VENDOR / AS4_BMS_NAME must match the OS4DSP registration
(Software Vendor Name / Product Name). Identity env vars are required —
defaults are refused so a forgotten export cannot lodge under the wrong name.
All four documents travel in ONE attachment, separated by record delimiters —
see `bulk_payload` in SBR.jl.
=#
@use "../SBR.jl" Env sts endpoints payevnt_message
@use "../ebMS3.jl" UserMessage Part Receipt EbMSError TransportError push pull
@use "../WSTrust.jl" issue_token TokenCache current_token
@use "../Keystore.jl" load
@use "./suite_fixtures.jl" payload

const suite = expanduser(get(ENV, "AS4_SUITE", ""))
isempty(suite) && error("set AS4_SUITE to the ATO PAYEVNT conformance suite package — licensed material, held outside this repo and deliberately not defaulted")
const scenario = joinpath(suite, "CONF-ATO-PAYEVNT-BULK-001")
const ABN = "67094544519"  # YALACT P/L — payer in BULK-001, must match the credential entity

require_live_identity!() = begin
  missing = String[]
  for k in ("AS4_PRODUCT_ID", "AS4_BMS_VENDOR", "AS4_BMS_NAME")
    isempty(strip(get(ENV, k, ""))) && push!(missing, k)
  end
  isempty(missing) || error(
    "live probe requires $(join(missing, ", ")). " *
    "These must match the DSP's OS4DSP registration; silent defaults are refused.")
end

require_live_identity!()
const product_id = ENV["AS4_PRODUCT_ID"]
const bms = (ENV["AS4_BMS_VENDOR"], ENV["AS4_BMS_NAME"], get(ENV, "AS4_BMS_VERSION", "1.0"))

cred = load(expanduser(ENV["AS4_KEYSTORE"]), ENV["AS4_PASSWORD"]; id="ABRD:$(ABN)_YALACT129")
@info "credential" cred.abn cred.legal_name cred.not_after

doc(name) = payload(joinpath(scenario, name))

msg, ids = payevnt_message(
  doc("CONF-ATO-PAYEVNT-BULK-001_Submit_Request_01.xml"),
  [doc("CONF-ATO-PAYEVNTEMP-BULK-001_Submit_Request_0$i.xml") for i in 2:4];
  abn=ABN, product_id=product_id, bms=bms)
@info "message properties" msg.properties
@info "record delimiters" ids payload_bytes = length(msg.parts[1].bytes)

s, eps = sts(Env.EVTE), endpoints(Env.EVTE)
cache = TokenCache()
token = current_token(cache, cred, s.url, s.applies_to)
@info "STS token issued" expires = token.expires

@info "pushing" eps.bulk_push msg.message_id
r = try
  push(eps.bulk_push, msg; cred=cred, assertion=token.assertion)
catch e
  @error "push failed" exception = e
  exit(1)
end

if r isa Receipt
  @info "RECEIPT — accepted into the bulk channel" r.message_id r.ref_to_message_id length(r.digests)
elseif r isa EbMSError
  @error "ebMS error signal" r.code r.severity r.short r.category r.detail
  exit(2)
else
  @info "unexpected response type" typeof(r) r
  exit(3)
end

@info "polling for the business response (selective pull)…"
deadline = time() + parse(Int, get(ENV, "AS4_POLL_SECS", "150"))
while time() < deadline
  sleep(15)
  token = current_token(cache, cred, s.url, s.applies_to)
  resp = try
    pull(eps.bulk_pull, msg.message_id; cred=cred, assertion=token.assertion)
  catch e
    @error "pull failed" exception = e
    break
  end
  resp === nothing && (println("  …empty channel (EBMS:0006), still processing"); continue)
  if resp isa UserMessage
    @info "BUSINESS RESPONSE" resp.service resp.action length(resp.parts)
    for p in resp.parts
      println("── part $(p.name) ($(p.mime)) ──")
      println(String(copy(p.bytes)))
    end
  else
    @info "pulled signal" resp
  end
  exit(0)
end
@info "no business response before deadline — poll again later with the MessageId above" msg.message_id
