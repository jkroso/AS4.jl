#=
Live EVTE PAYEVNT submit — run manually, never in CI:

  AS4_KEYSTORE=/path/to/evte.keystore.xml \
  AS4_PASSWORD=… \
  AS4_SUITE=~/Desktop/SBR-conformance/payevnt-suite/inner \
  julia --project=. test/live_payevnt.jl

Pushes conformance scenario BULK-001 (PAYEVNT + 3× PAYEVNTEMP) to the EVTE
bulk channel as the matching test entity (YALACT129), then selective-pulls
for the business response. AS4_PRODUCT_ID is the ATO-allocated EVTE product ID.
All four documents travel in ONE attachment, separated by record delimiters —
see `bulk_payload` in SBR.jl.
=#
@use "../SBR.jl" Env sts endpoints payevnt_message
@use "../ebMS3.jl" UserMessage Part Receipt EbMSError TransportError push pull
@use "../WSTrust.jl" issue_token
@use "../Keystore.jl" load
@use Dates: now, UTC, format, @dateformat_str

const suite = expanduser(get(ENV, "AS4_SUITE", "/path/to/payevnt-suite/inner"))
const scenario = joinpath(suite, "CONF-ATO-PAYEVNT-BULK-001")
const ABN = "67094544519"  # YALACT P/L — payer in BULK-001, must match the credential entity

cred = load(expanduser(ENV["AS4_KEYSTORE"]), ENV["AS4_PASSWORD"]; id="ABRD:$(ABN)_YALACT129")
@info "credential" cred.abn cred.legal_name cred.not_after

today = format(now(UTC), dateformat"yyyy-mm-dd")
stamp = format(now(UTC), dateformat"yyyy-mm-dd\THH:MM:SS.sss\Z")
"Conformance payloads ship with empty date fields for the DSP to populate."
fill_dates(xml) = replace(replace(xml,
    "<tns:MessageTimestampGenerationDt></tns:MessageTimestampGenerationDt>" =>
    "<tns:MessageTimestampGenerationDt>$stamp</tns:MessageTimestampGenerationDt>"),
  r"<tns:(\w+D)></tns:\1>" => SubstitutionString("<tns:\\1>$today</tns:\\1>"))

payload(name) = Vector{UInt8}(fill_dates(read(joinpath(scenario, name), String)))

msg, ids = payevnt_message(
  payload("CONF-ATO-PAYEVNT-BULK-001_Submit_Request_01.xml"),
  [payload("CONF-ATO-PAYEVNTEMP-BULK-001_Submit_Request_0$i.xml") for i in 2:4];
  abn=ABN, product_id=get(ENV, "AS4_PRODUCT_ID", ""),
  bms=("Example", "Example", "0.1.0"))
@info "message properties" msg.properties
@info "record delimiters" ids payload_bytes = length(msg.parts[1].bytes)

s, eps = sts(Env.EVTE), endpoints(Env.EVTE)
token = issue_token(cred, s.url, s.applies_to)
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
