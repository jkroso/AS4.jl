@use "github.com/jkroso/Prospects.jl" ["Enum.jl" @Enum]
@use "./ebMS3.jl" UserMessage Part push pull sync_call Receipt EbMSError xmlescape
@use "./WSTrust.jl" TokenCache current_token
@use "./Keystore.jl" Credential

const ATO_ABN = "51824753556"
const ABN_TYPE = "http://abr.gov.au/PartyIdType/ABN"
const TAN_TYPE = "http://ato.gov.au/PartyIdType/TAN"
const WPN_TYPE = "http://ato.gov.au/PartyIdType/WPN"

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

"From-party for a payer with a withholding payer number rather than an ABN."
wpn_party(wpn) = (replace(wpn, " " => ""), WPN_TYPE, "http://sbr.gov.au/ato/Role/Business")

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

service(key) = begin
  svc = get(SERVICES, key, nothing)
  svc === nothing && error("unknown SBR service $key — known: $(join(keys(SERVICES), ", "))")
  svc
end

# `from` defaults to the lodging party implied by abn/agent_tan; pass it
# explicitly for the cases those two don't cover, e.g. `wpn_party`.
addressed(svc, parts; abn=nothing, product_id, bms, agent_tan=nothing,
          from=agent_tan === nothing ? business_party(abn) : agent_party(agent_tan)) = UserMessage(
  from=from, to=ato_party(), service=svc.service, action=svc.action,
  properties=mandatory_properties(product_id, bms), parts=parts)

"""
A single-document service call (Single-Sync: AS, CTR, PAYEVNTRECON). Bulk
services carry many logical documents in one delimited attachment and are
built by `payevnt_message` instead.
"""
service_message(key, payload; kwargs...) = begin
  svc = service(key)
  svc.mep == :bulk && error("$key is a bulk service — build it with payevnt_message(parent, children; …) so the documents get record delimiters")
  addressed(svc, [Part(payload; name=svc.doc, doctype="BASE", mime="text/xml")]; kwargs...)
end

# ── CHRP bulk/batch payload assembly ─────────────────────────────────────────
#
# A bulk/batch request carries exactly ONE attachment holding every logical
# document, each *preceded* by a <Record_Delimiter/> naming it — the delimiter
# carries the identity information that PartProperties carries for a single
# document (ATO ebMS3 Implementation Guide; SBR SDK "Create MIME part for the
# Batch request"). One MIME part per document instead earns
# CMN.ATO.GEN.UNEXPECTEDNUMPAYLOADS back from the business service.

record(io, id, name, doctype, related, bytes) = begin
  write(io, """<Record_Delimiter DocumentID="$(xmlescape(id))" DocumentName="$(xmlescape(name))" """ *
            """DocumentType="$doctype" RelatedDocumentID="$(xmlescape(related))"/>\n""")
  write(io, bytes, '\n')
  id
end

"""
Assemble the single attachment for a bulk/batch request from `parent =>
children` groups — one group per parent in the transmission, each document
given as `"NAME" => bytes`.

DocumentIDs are allocated `"\$group.\$n"`: the parent takes `.1` and its
children `.2`, `.3`, … . That is the identifier the ATO echoes back in
`tns:Location.Instance.Identifier` to pin an error to one record, so the
returned `ids` (in transmission order) is what lets a caller map a response
event back to the document that caused it.
"""
bulk_payload(groups::AbstractVector) = begin
  io, ids = IOBuffer(), String[]
  for (g, (parent, children)) in enumerate(groups)
    pid = record(io, "$g.1", first(parent), "PARENT", "", last(parent))
    push!(ids, pid)
    for (n, child) in enumerate(children)
      push!(ids, record(io, "$g.$(n + 1)", first(child), "CHILD", pid, last(child)))
    end
  end
  (take!(io), ids)
end

"A single parent and its children — the ordinary Bulk (as opposed to Batch) case."
bulk_payload(parent::Pair, children::AbstractVector) = bulk_payload([parent => children])

"""
STP pay event (Hybrid Bulk: push to bulk_push, selective-pull the response).
`parent` is the PAYEVNT document's bytes and `children` the PAYEVNTEMP ones;
pass `groups` instead to put several payers in one Batch transmission.

Returns `(msg, ids)` — keep `ids` to reconcile the response's error locations
back to individual records, per `bulk_payload`.
"""
payevnt_message(parent, children; kind=:submit, kwargs...) =
  payevnt_message([("PAYEVNT" => parent) => ["PAYEVNTEMP" => c for c in children]]; kind, kwargs...)

payevnt_message(groups::AbstractVector; kind=:submit, kwargs...) = begin
  svc = service(Symbol(:payevnt_, kind))
  bytes, ids = bulk_payload(groups)
  # The attachment describes the transmission, not any one document: per-document
  # identity lives in the record delimiters. It still needs a DocumentType —
  # WIG Table 22 marks that "N/A" for a Bulk/Batch push, but EVTE rejects the
  # message without one (CMN.ATO.EBMS.001, FieldId "Attachment-DocumentType").
  (addressed(svc, [Part(bytes; name="PAYEVNT", doctype="BASE", mime="text/xml")]; kwargs...), ids)
end

"Activity statement interactions: `as_message(:get | :validate | :submit, payload; …)`."
as_message(kind::Symbol, payload; kwargs...) = service_message(Symbol(:as_, kind), payload; kwargs...)

const CACHES = Dict{Tuple{String,String},TokenCache}()
const CACHES_LOCK = ReentrantLock()

"""
The process-wide token cache for one credential against one environment's STS.

A default of `TokenCache()` would be a fresh cache per call, so every `lodge`
and every `collect_response` would mint its own SAML assertion — and collecting
a bulk response means polling. One token lasts 30 minutes and covers every SBR
service, so they share this instead. Pass `cache=TokenCache()` explicitly to
opt out.
"""
token_cache(env, cred::Credential) = lock(CACHES_LOCK) do
  get!(TokenCache, CACHES, (sts(env).url, cred.id))
end

"""
Which MEP a service URI uses, from the `SERVICES` registry.

`:bulk` → BulkBatch-async-push; anything else → Single-sync. Unknown service
URIs default to `:sync` so a typo still hits a single-sync endpoint rather than
the bulk channel (which would reject a non-delimited payload).
"""
mep_for(service::AbstractString) = begin
  for (_, svc) in SERVICES
    svc.service == service && return svc.mep
  end
  :sync
end

"Push URL for a message's service under `env`."
lodge_url(env, msg::UserMessage) =
  mep_for(msg.service) == :bulk ? endpoints(env).bulk_push : endpoints(env).single_sync

"""
High-level lodgment: token (cached) → push → Receipt. For bulk services the
business response arrives later via `collect_response`.
"""
lodge(env, cred::Credential, msg::UserMessage; cache=token_cache(env, cred), retries=2) = begin
  s = sts(env)
  token = current_token(cache, cred, s.url, s.applies_to)
  push(lodge_url(env, msg), msg; cred=cred, assertion=token.assertion, retries=retries)
end

"Selective-pull the response to an earlier push. `nothing` = not ready yet, poll again."
collect_response(env, cred::Credential, ref::AbstractString; cache=token_cache(env, cred)) = begin
  s = sts(env)
  token = current_token(cache, cred, s.url, s.applies_to)
  pull(endpoints(env).bulk_pull, ref; cred=cred, assertion=token.assertion)
end