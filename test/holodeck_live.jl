#=
Live push against a local Holodeck B2B peer (test/holodeck/).

  ./test/holodeck/setup.sh && ./test/holodeck/start.sh
  julia --project=. test/holodeck_live.jl

Gating:
  • Default: skip cleanly if nothing answers on AS4_HOLODECK_URL (default
    http://127.0.0.1:8080/holodeckb2b/as4).
  • AS4_HOLODECK=1: require Holodeck — fail if the peer is down.

Also run via test/runtests.jl (same skip/require rules).
=#
@use "../ebMS3.jl" UserMessage Part push Receipt
@use "../XMLSig.jl" load_pem_keypair
@use Sockets: connect
@use Test...

const pair = load_pem_keypair(joinpath(@__DIR__, "fixtures/key.pem"),
                              joinpath(@__DIR__, "fixtures/cert.pem"))
const url = get(ENV, "AS4_HOLODECK_URL", "http://127.0.0.1:8080/holodeckb2b/as4")
const require = get(ENV, "AS4_HOLODECK", "") == "1"
const msg_in = joinpath(@__DIR__, "holodeck", "hb2b", "data", "msg_in")

"Is something accepting TCP on host:port parsed from `url`?"
peer_up(u::AbstractString) = begin
  m = match(r"^https?://([^/:]+)(?::(\d+))?", u)
  m === nothing && return false
  host, port = m[1], parse(Int, something(m[2], "80"))
  try
    sock = connect(host, port)
    close(sock)
    true
  catch
    false
  end
end

const up = peer_up(url)

@testset "Holodeck live push → Receipt" begin
  if !up
    if require
      @info "start Holodeck: cd test/holodeck && ./start.sh"
      @test false  # AS4_HOLODECK=1 but peer is down
    else
      @info "skip Holodeck live — peer not on $url (./test/holodeck/start.sh, or AS4_HOLODECK=1 to require)"
      @test true
    end
  else
    payload = Vector{UInt8}("<doc holodeck=\"$(time_ns())\"/>")
    msg = UserMessage(
      from=("org:as4jl", "urn:oasis:names:tc:ebcore:partyid-type:unregistered",
            "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/initiator"),
      to=("org:holodeck", "urn:oasis:names:tc:ebcore:partyid-type:unregistered",
          "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/responder"),
      service="urn:test", action="Deliver",
      parts=[Part(payload; name="DOC", doctype="BASE")])
    # verify_receipt (default true) checks NRI digests against the signed message.
    r = push(url, msg; cred=pair)
    @test r isa Receipt
    @test r.ref_to_message_id == msg.message_id
    @test !isempty(r.digests)  # Holodeck returns NRI; empty would still pass push
    # Delivery side: payload should land under data/msg_in (mmd + payload file).
    if isdir(msg_in)
      mid = replace(msg.message_id, "@" => "_")
      delivered = filter(f -> occursin(mid, f), readdir(msg_in))
      @test !isempty(delivered)
    else
      @test true  # peer may be remote; delivery dir is local-only
    end
  end
end
