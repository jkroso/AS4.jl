#=
BULK-001 live smoke against EVTE: dump outbound payload, push, pull, dump inbound.

  AS4_KEYSTORE=… AS4_PASSWORD=… AS4_PRODUCT_ID=28305 \
  AS4_BMS_VENDOR='…' AS4_BMS_NAME='…' AS4_BMS_VERSION=0.1.0 \
  AS4_SUITE=~/Desktop/Centient/DSP/SBR-conformance/payevnt-suite/inner \
  [AS4_SMOKE_DUMP=/tmp/as4-bulk001-smoke] \
  julia --project=. test/smoke_bulk001.jl
=#
@use "../SBR.jl" Env payevnt_message endpoints sts
@use "./suite_fixtures.jl" payload
@use "../Keystore.jl" load
@use "../ebMS3.jl" push pull Receipt EbMSError UserMessage
@use "../WSTrust.jl" TokenCache current_token

const suite = expanduser(ENV["AS4_SUITE"])
const dumpdir = expanduser(get(ENV, "AS4_SMOKE_DUMP", "/tmp/as4-bulk001-smoke"))
const sc = joinpath(suite, "CONF-ATO-PAYEVNT-BULK-001")
const ABN = "67094544519"
const bms = (ENV["AS4_BMS_VENDOR"], ENV["AS4_BMS_NAME"], get(ENV, "AS4_BMS_VERSION", "0.1.0"))
const poll_secs = parse(Int, get(ENV, "AS4_POLL_SECS", "180"))

mkpath(dumpdir)

parent = payload(joinpath(sc, "CONF-ATO-PAYEVNT-BULK-001_Submit_Request_01.xml"))
kids = [payload(joinpath(sc, "CONF-ATO-PAYEVNTEMP-BULK-001_Submit_Request_0$i.xml")) for i in 2:4]
msg, ids = payevnt_message(parent, kids; abn=ABN, product_id=ENV["AS4_PRODUCT_ID"], bms=bms)

write(joinpath(dumpdir, "outbound_payload.xml"), msg.parts[1].bytes)
open(joinpath(dumpdir, "outbound_properties.txt"), "w") do io
  for (k, v) in msg.properties
    println(io, "$k = $v")
  end
  println(io, "service = ", msg.service)
  println(io, "action = ", msg.action)
  println(io, "from = ", msg.from)
  println(io, "to = ", msg.to)
  println(io, "message_id = ", msg.message_id)
  println(io, "record_ids = ", ids)
  println(io, "attachment_name = ", msg.parts[1].name)
  println(io, "attachment_doctype = ", msg.parts[1].doctype)
  println(io, "attachment_bytes = ", length(msg.parts[1].bytes))
end
@info "outbound dumped" dumpdir message_id=msg.message_id payload_bytes=length(msg.parts[1].bytes)

cred = load(ENV["AS4_KEYSTORE"], ENV["AS4_PASSWORD"]; abn=ABN)
@info "credential" cred.abn cred.not_after
s, eps = sts(Env.EVTE), endpoints(Env.EVTE)
cache = TokenCache()
token = current_token(cache, cred, s.url, s.applies_to)
@info "STS token" expires=token.expires

@info "pushing" eps.bulk_push
r = push(eps.bulk_push, msg; cred=cred, assertion=token.assertion)
open(joinpath(dumpdir, "push_result.txt"), "w") do io
  println(io, "typeof = ", typeof(r))
  if r isa Receipt
    println(io, "receipt_message_id = ", r.message_id)
    println(io, "ref_to_message_id = ", r.ref_to_message_id)
    println(io, "nri_digests = ", length(r.digests))
    for (uri, dv) in r.digests
      println(io, "  ", uri, " => ", dv)
    end
  else
    println(io, sprint(show, r))
  end
end
@info "push result" typeof(r)
r isa Receipt || error("expected Receipt, got $(typeof(r))")

function poll_response(msg, cred, cache, s, eps, poll_secs)
  deadline = time() + poll_secs
  while time() < deadline
    sleep(10)
    tok = current_token(cache, cred, s.url, s.applies_to)
    resp = pull(eps.bulk_pull, msg.message_id; cred=cred, assertion=tok.assertion)
    resp === nothing || return resp
    @info "empty channel, still waiting"
  end
  nothing
end

got = poll_response(msg, cred, cache, s, eps, poll_secs)
got === nothing && error("no business response in $(poll_secs)s; message_id=$(msg.message_id)")

open(joinpath(dumpdir, "inbound_meta.txt"), "w") do io
  println(io, "typeof = ", typeof(got))
  if got isa UserMessage
    println(io, "service = ", got.service)
    println(io, "action = ", got.action)
    println(io, "message_id = ", got.message_id)
    println(io, "n_parts = ", length(got.parts))
    for (i, p) in enumerate(got.parts)
      println(io, "part$i name=", p.name, " mime=", p.mime, " bytes=", length(p.bytes))
    end
  else
    println(io, sprint(show, got))
  end
end

if got isa UserMessage
  for (i, p) in enumerate(got.parts)
    write(joinpath(dumpdir, "inbound_part_$(i)_$(isempty(p.name) ? "part" : p.name).xml"), p.bytes)
  end
  dest = normpath(joinpath(suite, "..", "results", "BULK-001_Submit_1"))
  mkpath(dest)
  for (i, p) in enumerate(got.parts)
    write(joinpath(dest, "$(isempty(p.name) ? "PAYEVNT" : p.name)_$i.xml"), p.bytes)
  end
  @info "inbound saved" dumpdir dest parts=length(got.parts)
else
  error("unexpected response $(typeof(got))")
end
