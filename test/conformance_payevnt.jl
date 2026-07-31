#=
PAYEVNT.0004 2020 conformance runner, driven by the ATO's Conformance Suite
package (ShareFile). Two modes:

Offline (default) — for every BULK scenario: build the message set (dates
filled), sign it, and verify the signature locally. Proves assembly for the
whole suite without touching the network.

  AS4_SUITE=/path/to/payevnt-suite/inner \
  julia --project=. test/conformance_payevnt.jl

Live — submit each scenario to EVTE and selective-pull the validation
response, saving what comes back next to the suite's expected responses:

  AS4_LIVE=1 AS4_KEYSTORE=… AS4_PASSWORD=… [AS4_PRODUCT_ID=…] \
  [AS4_SCENARIO=BULK-001] [AS4_AGENT=1] [AS4_POLL_SECS=150] \
  julia --project=. test/conformance_payevnt.jl

Per-scenario credentials are selected from the EVTE keystore by the payload's
lodging ABN (the intermediary's for agent scenarios, else the payer's).
BATCH-* scenarios are the BRRP batch channel — not implemented (the suite
notes bulk/CHRP certification is the requirement) and reported as skipped.
Agent scenarios are skipped in live mode unless AS4_AGENT=1: Example is a
self-lodger product.
=#
@use "../SBR.jl" Env sts endpoints SERVICES business_party agent_party wpn_party ato_party payevnt_message
@use "../ebMS3.jl" UserMessage Part envelope secure! push pull Receipt EbMSError TransportError
@use "../XMLSig.jl" verify load_pem_keypair
@use "../WSTrust.jl" issue_token
@use "../Keystore.jl" load
@use "./suite_fixtures.jl" payload
@use Test...

const suite = expanduser(get(ENV, "AS4_SUITE", "/path/to/payevnt-suite/inner"))
const live = get(ENV, "AS4_LIVE", "") == "1"
const only = get(ENV, "AS4_SCENARIO", "")


first_match(re, s) = (m = match(re, s); m === nothing ? nothing : m[1])

"One lodgment: a PAYEVNT parent plus its PAYEVNTEMP children, ready to send."
struct Submission
  scenario::String
  action::String            # Submit | Update | Adjust
  n::Int                    # 1-based within the (scenario, action)
  parent::String            # file path
  children::Vector{String}
  abn::String               # payer (Rp) ABN — or WPN when wpn is set
  wpn::Bool                 # payer identifies by Withholding Payer Number (BULK-006)
  agent_tan::Union{String,Nothing}
  agent_abn::Union{String,Nothing}
end
lodging_abn(s::Submission) = something(s.agent_abn, s.abn)

"""
Scan the suite directory into submissions + a skipped list. Multi-parent
actions (BULK-019) split their children evenly across parents in file order —
the suite's numbering is sequential per submission.
"""
manifest() = begin
  subs, skipped = Submission[], Tuple{String,String}[]
  for dir in sort(readdir(suite))
    startswith(dir, "CONF-ATO-PAYEVNT-") || continue
    scenario = replace(dir, "CONF-ATO-PAYEVNT-" => "")
    if startswith(scenario, "BATCH")
      Base.push!(skipped, (scenario, "BRRP batch channel not implemented"))
      continue
    end
    files = sort(readdir(joinpath(suite, dir)))
    for action in ("Submit", "Update", "Adjust")
      isreq(f) = occursin("_$(action)_Request_", f)
      parents = [f for f in files if isreq(f) && !occursin("PAYEVNTEMP", f)]
      children = [f for f in files if isreq(f) && occursin("PAYEVNTEMP", f)]
      isempty(parents) && continue
      length(children) % length(parents) == 0 ||
        error("$scenario $action: $(length(children)) children don't divide over $(length(parents)) parents")
      per = length(parents) == 0 ? 0 : length(children) ÷ length(parents)
      for (i, parent) in enumerate(parents)
        kids = children[(i-1)*per+1 : i*per]
        xml = read(joinpath(suite, dir, parent), String)
        abn = first_match(r"<tns:AustralianBusinessNumberId>(\d+)</tns:AustralianBusinessNumberId>", xml)
        wpn = abn === nothing ? first_match(r"<tns:WithholdingPayerNumberId>(\d+)</tns:WithholdingPayerNumberId>", xml) : nothing
        tan = first_match(r"<tns:TaxAgentNumberId>(\d+)</tns:TaxAgentNumberId>", xml)
        agent_abn = tan === nothing ? nothing :
          match(r"<tns:Int>.*?<tns:AustralianBusinessNumberId>(\d+)<"s, xml)[1]
        Base.push!(subs, Submission(scenario, action, i, joinpath(suite, dir, parent),
                                    [joinpath(suite, dir, k) for k in kids],
                                    something(abn, wpn), abn === nothing, tan, agent_abn))
      end
    end
  end
  subs, skipped
end


message(s::Submission; product_id=get(ENV, "AS4_PRODUCT_ID", "")) = begin
  from = s.agent_tan !== nothing ? agent_party(s.agent_tan) :
         s.wpn ? wpn_party(s.abn) : business_party(s.abn)
  payevnt_message(payload(s.parent), payload.(s.children);
    kind=Symbol(lowercase(s.action)), from=from, product_id=product_id,
    bms=("Example", "Example", "0.1.0"))
end

subs, skipped = manifest()
isempty(only) || (subs = [s for s in subs if startswith(s.scenario, only)])
for (scenario, why) in skipped
  println("SKIP $scenario — $why")
end

if !live
  # Offline: every submission assembles into a locally-verifiable signed message.
  pair = load_pem_keypair(joinpath(@__DIR__, "fixtures/key.pem"), joinpath(@__DIR__, "fixtures/cert.pem"))
  @testset "assemble + sign + verify: $(s.scenario) $(s.action) #$(s.n)" for s in subs
    msg, ids = message(s; product_id="OFFLINE")
    doc, atts = envelope(msg)
    secure!(doc, atts, pair)
    @test verify(doc; cert=pair.cert_der, attachments=Dict(atts))
    # One delimited attachment for the whole transmission, one DocumentID per document.
    @test length(msg.parts) == 1
    @test length(ids) == 1 + length(s.children)
  end
  println("\n$(length(subs)) submissions across $(length(unique(s.scenario for s in subs))) scenarios assembled and verified offline.")
else
  keystore = expanduser(ENV["AS4_KEYSTORE"])
  password = ENV["AS4_PASSWORD"]
  outdir = expanduser(get(ENV, "AS4_OUT", joinpath(dirname(suite), "results")))
  poll_secs = parse(Int, get(ENV, "AS4_POLL_SECS", "150"))
  s_, eps = sts(Env.EVTE), endpoints(Env.EVTE)
  tokens = Dict{String,Any}()  # lodging ABN → (cred, token)
  credential(abn) = get!(tokens, abn) do
    cred = load(keystore, password; abn=abn)
    (cred, issue_token(cred, s_.url, s_.applies_to))
  end
  results = Tuple{String,String}[]
  for s in subs
    label = "$(s.scenario) $(s.action) #$(s.n)"
    if s.agent_tan !== nothing && get(ENV, "AS4_AGENT", "") != "1"
      Base.push!(results, (label, "skipped (agent scenario; AS4_AGENT=1 to include)")); continue
    end
    if s.wpn
      Base.push!(results, (label, "skipped (WPN payer — EVTE keystore has no matching credential)")); continue
    end
    cred, token = credential(lodging_abn(s))
    msg, _ = message(s)
    @info "pushing" label lodging = lodging_abn(s) msg.message_id
    r = try
      push(eps.bulk_push, msg; cred=cred, assertion=token.assertion)
    catch e
      Base.push!(results, (label, "TRANSPORT: $(sprint(showerror, e))")); continue
    end
    r isa EbMSError && (Base.push!(results, (label, "EBMS $(r.code): $(r.detail)")); continue)
    r isa Receipt || (Base.push!(results, (label, "unexpected $(typeof(r))")); continue)
    deadline = time() + poll_secs
    got = nothing
    while time() < deadline && got === nothing
      sleep(15)
      got = try pull(eps.bulk_pull, msg.message_id; cred=cred, assertion=token.assertion)
      catch e
        Base.push!(results, (label, "PULL: $(sprint(showerror, e))")); break
      end
    end
    if got isa UserMessage
      dest = joinpath(outdir, "$(s.scenario)_$(s.action)_$(s.n)")
      mkpath(dest)
      for (i, p) in enumerate(got.parts)
        write(joinpath(dest, "$(p.name)_$i.xml"), p.bytes)
      end
      Base.push!(results, (label, "response: $(length(got.parts)) part(s) → $dest"))
    elseif got === nothing
      Base.push!(results, (label, "receipt OK; response not ready in $(poll_secs)s (poll later: $(msg.message_id))"))
    end
  end
  println("\n── live results")
  for (label, outcome) in results
    println("  $(rpad(label, 26)) $outcome")
  end
end
