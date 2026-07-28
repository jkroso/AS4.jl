@use "github.com/jkroso/Prospects.jl" ["Enum.jl" @Enum]
@use "./ebMS3.jl" UserMessage Part push pull sync_call Receipt EbMSError
@use "./WSTrust.jl" TokenCache current_token
@use "./Keystore.jl" Credential

const ATO_ABN = "51824753556"
const ABN_TYPE = "http://abr.gov.au/PartyIdType/ABN"
const TAN_TYPE = "http://ato.gov.au/PartyIdType/TAN"

@Enum Env EVTE PROD

# ATO SBR Physical End Points v4.2 (Feb 2026)
endpoints(env) = env == Env.EVTE ?
  (single_sync="https://test2.ato.sbr.gov.au/services/Single-sync",
   single_async="https://test2.ato.sbr.gov.au/services/Single-async",
   bulk_push="https://test2.ato.sbr.gov.au/services/BulkBatch-async-push",
   bulk_pull="https://test2.ato.sbr.gov.au/services/BulkBatch-async-pull",
   collect="https://test2.ato.sbr.gov.au/services/Collect-async") :
  (single_sync="https://prod2.ato.sbr.gov.au/services/Single-sync",
   single_async="https://prod2.ato.sbr.gov.au/services/Single-async-push-pull",
   bulk_push="https://prod2.ato.sbr.gov.au/services/BulkBatch-async-push",
   bulk_pull="https://prod2.ato.sbr.gov.au/services/BulkBatch-async-pull",
   collect="https://prod2.ato.sbr.gov.au/services/Collect-async")

sts(env) = env == Env.EVTE ?
  (url="https://softwareauthorisations.evte.ato.gov.au/R3.0/S007v1.3/service.svc",
   applies_to="https://test.sbr.gov.au/services") :
  (url="https://softwareauthorisations.ato.gov.au/R3.0/S007v1.3/service.svc",
   applies_to="https://sbr.gov.au/services")

"From-party for a business lodging its own obligations."
business_party(abn) = (replace(abn, " " => ""), ABN_TYPE, "http://sbr.gov.au/ato/Role/Business")

"From-party for a registered agent lodging on behalf of a client."
agent_party(tan) = (replace(tan, " " => ""), TAN_TYPE, "http://sbr.gov.au/ato/Role/Registered Agent")

ato_party() = (ATO_ABN, ABN_TYPE, "http://sbr.gov.au/agency")

# Service/Action URIs, verified against the ATO Service Registry (Jan 2026
# XLSX, "Service Actions" sheet, CollaborationInfo columns).
const SERVICES = Dict(
  :payevnt_submit => (service="http://sbr.gov.au/ato/payevnt/2020", action="Submit.004.00", doc="PAYEVNT", mep=:bulk),
  :payevnt_update => (service="http://sbr.gov.au/ato/payevnt/2020", action="Update.004.00", doc="PAYEVNTEMP", mep=:bulk),
  :payevnt_adjust => (service="http://sbr.gov.au/ato/payevnt/2020", action="Adjust.004.00", doc="PAYEVNT", mep=:bulk),
  :payevntrecon_list => (service="http://sbr.gov.au/ato/payevntrecon/2023", action="List.001.00", doc="PAYEVNTRECON", mep=:sync),
  :as_get => (service="http://sbr.gov.au/ato/as/2025", action="Get.004.00", doc="AS", mep=:sync),
  :as_validate => (service="http://sbr.gov.au/ato/as/2025", action="Validate.004.00", doc="AS", mep=:sync),
  :as_submit => (service="http://sbr.gov.au/ato/as/2025", action="Submit.004.00", doc="AS", mep=:sync),
  :ctr_submit => (service="http://sbr.gov.au/ato/ctr/2026", action="Submit.017.00", doc="CTR", mep=:sync),
  :ctr_validate => (service="http://sbr.gov.au/ato/ctr/2026", action="Validate.017.00", doc="CTR", mep=:sync))

mandatory_properties(product_id, (vendor, name, version)) =
  ["ProductID" => product_id, "BMS Vendor" => vendor, "BMS Name" => name, "BMS Version" => version]

service_message(key, payload; abn, product_id, bms, agent_tan=nothing) = begin
  svc = get(SERVICES, key, nothing)
  svc === nothing && error("unknown SBR service $key — known: $(join(keys(SERVICES), ", "))")
  UserMessage(
    from=agent_tan === nothing ? business_party(abn) : agent_party(agent_tan),
    to=ato_party(), service=svc.service, action=svc.action,
    properties=mandatory_properties(product_id, bms),
    parts=[Part(payload; name=svc.doc, doctype="BASE", mime="text/xml")])
end

"STP pay event (Hybrid Bulk: push to bulk_push, selective-pull the response)."
payevnt_message(payload; kwargs...) = service_message(:payevnt_submit, payload; kwargs...)

"Activity statement interactions: `as_message(:get | :validate | :submit, payload; …)`."
as_message(kind::Symbol, payload; kwargs...) = service_message(Symbol(:as_, kind), payload; kwargs...)

"""
High-level lodgment: token (cached) → push → Receipt. For bulk services the
business response arrives later via `collect_response`.
"""
lodge(env, cred::Credential, msg::UserMessage; cache=TokenCache(), retries=2) = begin
  s = sts(env)
  token = current_token(cache, cred, s.url, s.applies_to)
  # pay events are Bulk-Async; everything else (incl. payevntrecon list) is Single-Sync
  url = occursin("/payevnt/", msg.service) ? endpoints(env).bulk_push : endpoints(env).single_sync
  push(url, msg; cred=cred, assertion=token.assertion, retries=retries)
end

"Selective-pull the response to an earlier push. `nothing` = not ready yet, poll again."
collect_response(env, cred::Credential, ref::AbstractString; cache=TokenCache()) = begin
  s = sts(env)
  token = current_token(cache, cred, s.url, s.applies_to)
  pull(endpoints(env).bulk_pull, ref; cred=cred, assertion=token.assertion)
end