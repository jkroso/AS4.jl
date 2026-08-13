#=
PAYEVNT.0004 2020 conformance runner, driven by the ATO's Conformance Suite
package (ShareFile). Modes:

Offline (default) — for every BULK scenario: build the message set (dates
filled), sign it, and verify the signature locally. Proves assembly for the
whole suite without touching the network.

  AS4_SUITE=/path/to/payevnt-suite/inner \
  julia --project=. test/conformance_payevnt.jl

Live — submit each scenario to EVTE, selective-pull the validation response,
score business Error.Codes against the suite's expected Response, and write
results + a RUN.md provenance file:

  AS4_LIVE=1 AS4_KEYSTORE=… AS4_PASSWORD=… AS4_PRODUCT_ID=… \
  AS4_BMS_VENDOR=… AS4_BMS_NAME=… [AS4_BMS_VERSION=1.0] \
  [AS4_SCENARIO=BULK-001] [AS4_AGENT=1] [AS4_POLL_SECS=150] \
  julia --project=. test/conformance_payevnt.jl

Score-only — re-score an existing results directory without hitting the network
(uses the same business-code multiset comparison as live):

  AS4_SCORE_ONLY=1 [AS4_OUT=…/results] \
  julia --project=. test/conformance_payevnt.jl

Live mode is fail-closed on identity: AS4_PRODUCT_ID, AS4_BMS_VENDOR, and
AS4_BMS_NAME must be set (must match the DSP's OS4DSP registration). Defaults
are not accepted — silent wrong identity is how production access gets blocked.

Per-scenario credentials are selected from the EVTE keystore by the payload's
lodging ABN (the intermediary's for agent scenarios, else the payer's).
BATCH-* scenarios are the BRRP batch channel — not implemented (the suite
notes bulk/CHRP certification is the requirement) and reported as skipped.
Agent scenarios are skipped in live mode unless AS4_AGENT=1 (self-lodger
products do not exercise registered-agent paths).
=#
@use "../SBR.jl" Env sts endpoints SERVICES business_party agent_party wpn_party ato_party payevnt_message
@use "../ebMS3.jl" UserMessage Part envelope secure! push pull Receipt EbMSError TransportError
@use "../XMLSig.jl" verify load_pem_keypair
@use "../WSTrust.jl" issue_token TokenCache current_token
@use "../Keystore.jl" load
@use "./suite_fixtures.jl" payload expected_response_path score_response_files code_counts business_codes
@use Dates: now, UTC, format, @dateformat_str
@use Test...

const suite = expanduser(get(ENV, "AS4_SUITE", ""))
isempty(suite) && error("set AS4_SUITE to the ATO PAYEVNT conformance suite package — licensed material, held outside this repo and deliberately not defaulted")
const live = get(ENV, "AS4_LIVE", "") == "1"
const score_only = get(ENV, "AS4_SCORE_ONLY", "") == "1"
const only = get(ENV, "AS4_SCENARIO", "")

# ── Identity (MessageProperties) ──────────────────────────────────────────────

"""
Live EVTE MessageProperties must match OS4DSP registration exactly (Software
Vendor Name / Product Name / EVTE Product ID). Never hard-code a real DSP's
identity in this open-source package — supply via env.
"""
require_live_identity!() = begin
  missing = String[]
  for k in ("AS4_PRODUCT_ID", "AS4_BMS_VENDOR", "AS4_BMS_NAME")
    isempty(strip(get(ENV, k, ""))) && push!(missing, k)
  end
  isempty(missing) || error(
    "live mode requires $(join(missing, ", ")). " *
    "These must match the DSP's OS4DSP registration (Software Vendor Name / " *
    "Product Name / EVTE Product ID). Silent defaults are refused so a forgotten " *
    "export cannot regenerate a data-integrity failure against the ATO.")
end

bms_from_env() = (
  ENV["AS4_BMS_VENDOR"],
  ENV["AS4_BMS_NAME"],
  get(ENV, "AS4_BMS_VERSION", "1.0"))

# Offline / score-only may use placeholders — they never hit EVTE as a DSP.
bms_offline() = (
  get(ENV, "AS4_BMS_VENDOR", "Example Vendor"),
  get(ENV, "AS4_BMS_NAME", "Example Payroll"),
  get(ENV, "AS4_BMS_VERSION", "1.0"))

# ── Suite manifest ────────────────────────────────────────────────────────────

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
label_of(s::Submission) = "$(s.scenario) $(s.action) #$(s.n)"
result_dirname(s::Submission) = "$(s.scenario)_$(s.action)_$(s.n)"

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

message(s::Submission; product_id, bms) = begin
  from = s.agent_tan !== nothing ? agent_party(s.agent_tan) :
         s.wpn ? wpn_party(s.abn) : business_party(s.abn)
  payevnt_message(payload(s.parent), payload.(s.children);
    kind=Symbol(lowercase(s.action)), from=from, product_id=product_id, bms=bms)
end

# ── Scoring ───────────────────────────────────────────────────────────────────

"Format a code multiset for one-line display."
fmt_counts(d::AbstractDict) = isempty(d) ? "(none)" :
  join(["$k×$v" for (k, v) in sort!(collect(d); by=first)], ", ")

"""
Score one submission's on-disk result directory against the suite expected
Response. Returns a status string: PASS / FAIL / NO_RESULT / NO_EXPECTED.
"""
score_submission(s::Submission, outdir::AbstractString) = begin
  dest = joinpath(outdir, result_dirname(s))
  isdir(dest) || return ("NO_RESULT", nothing, nothing)
  actuals = sort(filter(p -> endswith(p, ".xml"), readdir(dest; join=true)))
  isempty(actuals) && return ("NO_RESULT", nothing, nothing)
  exp = expected_response_path(s.parent)
  exp === nothing && return ("NO_EXPECTED", nothing, nothing)
  ok, expc, actc = score_response_files(actuals, exp)
  (ok ? "PASS" : "FAIL", expc, actc)
end

score_all(subs, outdir) = begin
  rows = Tuple{String,String,Any,Any}[]
  for s in subs
    st, expc, actc = score_submission(s, outdir)
    Base.push!(rows, (label_of(s), st, expc, actc))
  end
  rows
end

print_score_table(rows) = begin
  npass = count(r -> r[2] == "PASS", rows)
  nfail = count(r -> r[2] == "FAIL", rows)
  nskip = length(rows) - npass - nfail
  println("\n── score (business Error.Code multiset vs suite expected)")
  for (label, st, expc, actc) in rows
    if st == "PASS"
      println("  PASS  $(rpad(label, 26)) $(fmt_counts(expc))")
    elseif st == "FAIL"
      println("  FAIL  $(rpad(label, 26)) expected $(fmt_counts(expc))  actual $(fmt_counts(actc))")
    else
      println("  $(rpad(st, 5)) $(rpad(label, 26))")
    end
  end
  println("\n$npass pass, $nfail fail, $nskip unscored (of $(length(rows)))")
  (npass, nfail, nskip)
end

# ── Load manifest ─────────────────────────────────────────────────────────────

subs, skipped = manifest()
isempty(only) || (subs = [s for s in subs if startswith(s.scenario, only)])
for (scenario, why) in skipped
  println("SKIP $scenario — $why")
end

# ── Score-only (no network) ───────────────────────────────────────────────────

if score_only
  outdir = expanduser(get(ENV, "AS4_OUT", joinpath(dirname(suite), "results")))
  rows = score_all(subs, outdir)
  _, nfail, _ = print_score_table(rows)
  exit(nfail == 0 ? 0 : 1)
end

# ── Offline assemble + sign ───────────────────────────────────────────────────

if !live
  pair = load_pem_keypair(joinpath(@__DIR__, "fixtures/key.pem"), joinpath(@__DIR__, "fixtures/cert.pem"))
  @testset "assemble + sign + verify: $(s.scenario) $(s.action) #$(s.n)" for s in subs
    msg, ids = message(s; product_id="OFFLINE", bms=bms_offline())
    doc, atts = envelope(msg)
    secure!(doc, atts, pair)
    @test verify(doc; cert=pair.cert_der, attachments=Dict(atts))
    @test length(msg.parts) == 1
    @test length(ids) == 1 + length(s.children)
  end
  println("\n$(length(subs)) submissions across $(length(unique(s.scenario for s in subs))) scenarios assembled and verified offline.")

# ── Live EVTE ─────────────────────────────────────────────────────────────────

else
  require_live_identity!()
  product_id = ENV["AS4_PRODUCT_ID"]
  bms = bms_from_env()
  keystore = expanduser(ENV["AS4_KEYSTORE"])
  password = ENV["AS4_PASSWORD"]
  outdir = expanduser(get(ENV, "AS4_OUT", joinpath(dirname(suite), "results")))
  poll_secs = parse(Int, get(ENV, "AS4_POLL_SECS", "150"))
  s_, eps = sts(Env.EVTE), endpoints(Env.EVTE)
  # Per-ABN credential + TokenCache so long suite runs refresh before expiry.
  sessions = Dict{String,Tuple{Any,TokenCache}}()
  session(abn) = get!(sessions, abn) do
    (load(keystore, password; abn=abn), TokenCache())
  end
  token_for(abn) = begin
    cred, cache = session(abn)
    (cred, current_token(cache, cred, s_.url, s_.applies_to))
  end

  started = now(UTC)
  # (label, outcome, message_id, score_status)
  results = NamedTuple{(:label, :outcome, :message_id, :score),
                       Tuple{String,String,String,String}}[]
  for s in subs
    lab = label_of(s)
    if s.agent_tan !== nothing && get(ENV, "AS4_AGENT", "") != "1"
      Base.push!(results, (label=lab, outcome="skipped (agent scenario; AS4_AGENT=1 to include)",
                           message_id="", score="SKIP"))
      continue
    end
    if s.wpn
      Base.push!(results, (label=lab, outcome="skipped (WPN payer — EVTE keystore has no matching credential)",
                           message_id="", score="SKIP"))
      continue
    end
    cred, token = token_for(lodging_abn(s))
    msg, _ = message(s; product_id=product_id, bms=bms)
    @info "pushing" label=lab lodging=lodging_abn(s) msg.message_id properties=msg.properties
    r = try
      push(eps.bulk_push, msg; cred=cred, assertion=token.assertion)
    catch e
      Base.push!(results, (label=lab, outcome="TRANSPORT: $(sprint(showerror, e))",
                           message_id=msg.message_id, score="ERROR"))
      continue
    end
    if r isa EbMSError
      Base.push!(results, (label=lab, outcome="EBMS $(r.code): $(r.detail)",
                           message_id=msg.message_id, score="ERROR"))
      continue
    end
    if !(r isa Receipt)
      Base.push!(results, (label=lab, outcome="unexpected $(typeof(r))",
                           message_id=msg.message_id, score="ERROR"))
      continue
    end
    # Poll in a function so soft-scope cannot leave `got` stuck as nothing.
    pull_err = Ref{Any}(nothing)
    got = let mid=msg.message_id, abn=lodging_abn(s), c=cred, dline=time()+poll_secs
      resp = nothing
      while time() < dline && resp === nothing
        sleep(15)
        _, tok = token_for(abn)
        resp = try
          pull(eps.bulk_pull, mid; cred=c, assertion=tok.assertion)
        catch e
          pull_err[] = e
          break
        end
      end
      resp
    end
    if pull_err[] !== nothing
      Base.push!(results, (label=lab, outcome="PULL: $(sprint(showerror, pull_err[]))",
                           message_id=msg.message_id, score="ERROR"))
      continue
    end
    if got isa UserMessage
      dest = joinpath(outdir, result_dirname(s))
      mkpath(dest)
      for (i, p) in enumerate(got.parts)
        write(joinpath(dest, "$(isempty(p.name) ? "PAYEVNT" : p.name)_$i.xml"), p.bytes)
      end
      st, expc, actc = score_submission(s, outdir)
      detail = st == "PASS" ? "PASS $(fmt_counts(expc))" :
               st == "FAIL" ? "FAIL expected $(fmt_counts(expc)) actual $(fmt_counts(actc))" : st
      Base.push!(results, (label=lab,
                           outcome="response: $(length(got.parts)) part(s) → $dest [$detail]",
                           message_id=msg.message_id, score=st))
    elseif got === nothing
      Base.push!(results, (label=lab,
                           outcome="receipt OK; response not ready in $(poll_secs)s (poll later: $(msg.message_id))",
                           message_id=msg.message_id, score="NO_RESULT"))
    end
  end

  println("\n── live results")
  for row in results
    println("  $(rpad(row.label, 26)) $(row.outcome)")
  end

  # Re-score everything present under outdir (includes this run + prior artefacts).
  score_rows = score_all(subs, outdir)
  npass, nfail, nskip = print_score_table(score_rows)

  # Provenance for ATO tickets (MessageIds, identity used, wall clock).
  run_md = joinpath(outdir, "RUN.md")
  open(run_md, "w") do io
    println(io, "# PAYEVNT.0004 2020 live run")
    println(io)
    println(io, "| | |")
    println(io, "|---|---|")
    println(io, "| Started (UTC) | $(format(started, dateformat"yyyy-mm-ddTHH:MM:SS")) |")
    println(io, "| Finished (UTC) | $(format(now(UTC), dateformat"yyyy-mm-ddTHH:MM:SS")) |")
    println(io, "| Suite | `$suite` |")
    println(io, "| ProductID | `$(product_id)` |")
    println(io, "| BMS Vendor | `$(bms[1])` |")
    println(io, "| BMS Name | `$(bms[2])` |")
    println(io, "| BMS Version | `$(bms[3])` |")
    println(io, "| Score | $npass pass, $nfail fail, $nskip unscored |")
    println(io)
    println(io, "## Submissions")
    println(io)
    println(io, "| Label | MessageId | Score | Outcome |")
    println(io, "|---|---|---|---|")
    for row in results
      mid = isempty(row.message_id) ? "—" : "`$(row.message_id)`"
      println(io, "| $(row.label) | $mid | $(row.score) | $(replace(row.outcome, "|" => "\\|")) |")
    end
  end
  println("\nWrote provenance → $run_md")
  exit(nfail == 0 ? 0 : 1)
end
