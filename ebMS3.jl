@use "github.com/jkroso/Prospects.jl" @struct
@use "./XMLSig.jl" DS WSSE WSU S12 EB SAML2 sign! graft! verify
@use "./MIME.jl" MimePart mime_parse mime_encode
@use EzXML: parsexml, root, Document, Node
@use CodecZlib: GzipCompressor, GzipDecompressor
@use UUIDs: uuid4
@use Dates: now, UTC, format, @dateformat_str
@use Base64: base64encode
@use Downloads

const TSFORMAT = dateformat"yyyy-mm-dd\THH:MM:SS.sss\Z"

"""
Right-hand side of generated `eb:MessageId`s and Content-IDs. RFC 2822 wants a
domain the sender actually controls, and the receiving gateway logs it, so set
it before sending anything:

    MESSAGE_ID_DOMAIN[] = "as4.yourcompany.com.au"

The default is deliberately an RFC 2606 `.invalid` name: a MessageId that
reaches a gateway still carrying it is a configuration bug you want to notice.
"""
const MESSAGE_ID_DOMAIN = Ref("as4.invalid")

newid() = "$(uuid4())@$(MESSAGE_ID_DOMAIN[])"

xmlescape(s) = replace(string(s), '&'=>"&amp;", '<'=>"&lt;", '>'=>"&gt;", '"'=>"&quot;")

"One business payload: raw bytes plus the ebMS PartProperties that describe them."
@struct struct Part
  bytes::Vector{UInt8}
  name::String = ""          # PartProperty DocumentName, e.g. "PAYEVNT"
  doctype::String = ""       # PartProperty DocumentType: BASE | SCHEDULE
  mime::String = "text/xml"  # of the *uncompressed* document
  cid::String = newid()
end
Part(bytes::Union{Vector{UInt8},AbstractString}; kwargs...) = Part(bytes=Vector{UInt8}(bytes); kwargs...)

"An ebMS3 UserMessage. Parties are `(id, id_type_uri, role_uri)` tuples."
@struct struct UserMessage
  from::Tuple{String,String,String}
  to::Tuple{String,String,String}
  service::String
  action::String
  agreement::Union{String,Nothing} = nothing
  conversation_id::String = string(uuid4())
  message_id::String = newid()
  properties::Vector{Pair{String,String}} = Pair{String,String}[]
  parts::Vector{Part} = Part[]
end

party(tag, (id, type, role)) = """<eb:$tag><eb:PartyId type="$(xmlescape(type))">$(xmlescape(id))</eb:PartyId><eb:Role>$(xmlescape(role))</eb:Role></eb:$tag>"""

partinfo(p::Part) = begin
  props = ["PartID" => p.cid, "MimeType" => p.mime, "CompressionType" => "application/gzip"]
  isempty(p.name) || push!(props, "DocumentName" => p.name)
  isempty(p.doctype) || push!(props, "DocumentType" => p.doctype)
  xml = join("""<eb:Property name="$(xmlescape(k))">$(xmlescape(v))</eb:Property>""" for (k, v) in props)
  """<eb:PartInfo href="cid:$(p.cid)"><eb:PartProperties>$xml</eb:PartProperties></eb:PartInfo>"""
end

"""
Build the SOAP 1.2 envelope for a UserMessage. Returns `(doc, attachments)`
where attachments is an ordered `cid => gzipped bytes` list. The eb:Messaging
header and empty body carry `wsu:Id` anchors ("ebmessaging", "soapbody") for
the WS-Security signature.
"""
envelope(msg::UserMessage; timestamp=now(UTC)) = begin
  collab = (msg.agreement === nothing ? "" : "<eb:AgreementRef>$(xmlescape(msg.agreement))</eb:AgreementRef>") *
    "<eb:Service>$(xmlescape(msg.service))</eb:Service><eb:Action>$(xmlescape(msg.action))</eb:Action>" *
    "<eb:ConversationId>$(xmlescape(msg.conversation_id))</eb:ConversationId>"
  props = isempty(msg.properties) ? "" :
    "<eb:MessageProperties>" *
    join("""<eb:Property name="$(xmlescape(k))">$(xmlescape(v))</eb:Property>""" for (k, v) in msg.properties) *
    "</eb:MessageProperties>"
  payloads = isempty(msg.parts) ? "" : "<eb:PayloadInfo>$(join(map(partinfo, msg.parts)))</eb:PayloadInfo>"
  xml = """<s:Envelope xmlns:s="$S12" xmlns:eb="$EB" xmlns:wsu="$WSU"><s:Header>""" *
    """<eb:Messaging wsu:Id="ebmessaging" s:mustUnderstand="true"><eb:UserMessage>""" *
    """<eb:MessageInfo><eb:Timestamp>$(format(timestamp, TSFORMAT))</eb:Timestamp>""" *
    """<eb:MessageId>$(xmlescape(msg.message_id))</eb:MessageId></eb:MessageInfo>""" *
    """<eb:PartyInfo>$(party("From", msg.from))$(party("To", msg.to))</eb:PartyInfo>""" *
    """<eb:CollaborationInfo>$collab</eb:CollaborationInfo>$props$payloads""" *
    """</eb:UserMessage></eb:Messaging></s:Header><s:Body wsu:Id="soapbody"/></s:Envelope>"""
  parsexml(xml), [p.cid => transcode(GzipCompressor, p.bytes) for p in msg.parts]
end

# ── WS-Security (SBR profile: BST + opaque SAML assertion + 4-part signature) ─

const X509V3 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
const B64ENC = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"

"""
Add the WS-Security header per the SBR ebMS3 profile: an X509 BinarySecurityToken
(the machine credential), the STS-issued `saml2:EncryptedAssertion` inserted
verbatim (pass `nothing` before a token is held), and one signature over
eb:Messaging + assertion + body + every attachment. `cred` needs `.key` +
`.cert_der` (a `Keystore.Credential` or test keypair).

`attachments` keeps its order in the signature when given as pairs, so the
ds:Reference sequence matches the order the parts go on the wire.
"""
secure!(doc::Document, attachments, cred, assertion=nothing) = begin
  header = Base.findfirst("//s:Header", root(doc), RNS)
  header === nothing && error("no SOAP header")
  secnode = graft!(header, root(parsexml(
    """<wsse:Security xmlns:wsse="$WSSE" xmlns:wsu="$WSU" s:mustUnderstand="true" xmlns:s="$S12"/>""")))
  # WIG sample layout: EncryptedAssertion, then BST, then Signature (strict gateways enforce order)
  if assertion !== nothing
    # wsu:Id goes on through the DOM. The assertion is the STS's own XML and we
    # do not control its namespace declarations; rewriting the opening tag by
    # regex produces a duplicate xmlns:wsu — and unparseable XML — whenever it
    # already declares one.
    graft!(secnode, assertion)["wsu:Id"] = "assertion"
  end
  graft!(secnode, root(parsexml(
    """<wsse:BinarySecurityToken xmlns:wsse="$WSSE" xmlns:wsu="$WSU" EncodingType="$B64ENC" ValueType="$X509V3" wsu:Id="signingCert">$(base64encode(cred.cert_der))</wsse:BinarySecurityToken>""")))
  ids = assertion === nothing ? ["ebmessaging", "soapbody"] : ["ebmessaging", "assertion", "soapbody"]
  str = """<ds:KeyInfo><wsse:SecurityTokenReference xmlns:wsse="$WSSE"><wsse:Reference URI="#signingCert" ValueType="$X509V3"/></wsse:SecurityTokenReference></ds:KeyInfo>"""
  sign!(doc, secnode, ids, cred; attachments=attachments, keyinfo=str)
  doc
end

# ── response parsing ──────────────────────────────────────────────────────────

"A positive ebMS3 acknowledgment, with non-repudiation digests when present."
@struct struct Receipt
  message_id::String
  ref_to_message_id::String
  digests::Vector{Pair{String,String}} = Pair{String,String}[]  # reference URI => DigestValue
end

"An ebMS3 Error signal."
struct EbMSError <: Exception
  code::String
  severity::String
  short::String
  category::String
  detail::String
  ref_to_message_id::String
end
Base.showerror(io::IO, e::EbMSError) = print(io, "EbMSError $(e.code) ($(e.severity)) $(e.short): $(e.detail)")

"EBMS:0006 — a pull found nothing queued. The 'keep polling' signal, not a failure."
isempty_mpc(e::EbMSError) = e.code == "EBMS:0006"

"Transport- or SOAP-level failure with no ebMS Messaging header to interpret."
struct TransportError <: Exception
  message::String
end
Base.showerror(io::IO, e::TransportError) = print(io, "TransportError: ", e.message)

const RNS = ["s"=>S12, "eb"=>EB, "ds"=>DS, "ebbp"=>"http://docs.oasis-open.org/ebxml-bp/ebbp-signals-2.0"]

text(node, xpath) = begin
  n = Base.findfirst(xpath, node, RNS)
  n === nothing ? "" : n.content
end

attr(node, name) = haskey(node, name) ? node[name] : ""

parse_party(node, tag) = begin
  pid = Base.findfirst("./eb:PartyInfo/eb:$tag/eb:PartyId", node, RNS)
  role = text(node, "./eb:PartyInfo/eb:$tag/eb:Role")
  pid === nothing ? ("", "", role) : (pid.content, attr(pid, "type"), role)
end

parse_usermessage(um::Node, attachments::Dict{String,Vector{UInt8}}) = begin
  parts = Part[]
  for pi in Base.findall("./eb:PayloadInfo/eb:PartInfo", um, RNS)
    href = attr(pi, "href")
    cid = startswith(href, "cid:") ? href[5:end] : href
    haskey(attachments, cid) || continue
    props = Dict(p["name"] => p.content for p in Base.findall(".//eb:PartProperties/eb:Property", pi, RNS))
    bytes = attachments[cid]
    get(props, "CompressionType", "") == "application/gzip" && (bytes = transcode(GzipDecompressor, bytes))
    push!(parts, Part(bytes=bytes, cid=cid,
                      name=get(props, "DocumentName", ""), doctype=get(props, "DocumentType", ""),
                      mime=get(props, "MimeType", "")))
  end
  UserMessage(
    from=parse_party(um, "From"), to=parse_party(um, "To"),
    service=text(um, "./eb:CollaborationInfo/eb:Service"),
    action=text(um, "./eb:CollaborationInfo/eb:Action"),
    agreement=(a = text(um, "./eb:CollaborationInfo/eb:AgreementRef"); isempty(a) ? nothing : a),
    conversation_id=text(um, "./eb:CollaborationInfo/eb:ConversationId"),
    message_id=text(um, "./eb:MessageInfo/eb:MessageId"),
    properties=[p["name"] => p.content for p in Base.findall("./eb:MessageProperties/eb:Property", um, RNS)],
    parts=parts)
end

"A short printable excerpt of a response body, for diagnostics."
snippet(bytes::Vector{UInt8}, n=200) = begin
  s = String(copy(bytes[1:min(end, n)]))
  strip(replace(isvalid(String, s) ? s : repr(bytes[1:min(end, 40)]), r"\s+" => " ")) *
    (length(bytes) > n ? "…" : "")
end

"""
Parse a response body into a `Receipt`, `EbMSError`, or `UserMessage`.
Throws `TransportError` for SOAP faults without an ebMS Messaging header, and
for bodies that aren't parseable at all — a gateway or proxy that answers with
HTML or nothing must not surface as an XML library error. `status` is carried
only for the message: ebMS3 signals legitimately arrive with HTTP 500, so a
non-2xx body is still parsed before being judged.
"""
parse_response(body::Vector{UInt8}, content_type::AbstractString; status=200) = begin
  at = "HTTP $status"
  parts = try
    occursin("multipart/related", content_type) ? mime_parse(body, content_type) :
            [MimePart(String(content_type), body)]
  catch e
    throw(TransportError("$at: unreadable multipart body — $(sprint(showerror, e))"))
  end
  isempty(parts) && throw(TransportError("$at: empty response body"))
  doc = try
    parsexml(parts[1].bytes)
  catch e
    throw(TransportError("$at: response is not XML — $(snippet(parts[1].bytes))"))
  end
  attachments = Dict(p.id => p.bytes for p in parts[2:end])
  messaging = Base.findfirst("//eb:Messaging", root(doc), RNS)
  if messaging === nothing
    reason = text(root(doc), "//s:Fault//s:Text")
    throw(TransportError(isempty(reason) ? "$at: no eb:Messaging in response" : "$at: SOAP fault: $reason"))
  end
  um = Base.findfirst("./eb:UserMessage", messaging, RNS)
  um === nothing || return parse_usermessage(um, attachments)
  info(x) = text(messaging, "./eb:SignalMessage/eb:MessageInfo/eb:$x")
  err = Base.findfirst("./eb:SignalMessage/eb:Error", messaging, RNS)
  if err !== nothing
    return EbMSError(attr(err, "errorCode"), attr(err, "severity"),
                     attr(err, "shortDescription"), attr(err, "category"),
                     text(err, "./eb:ErrorDetail"), info("RefToMessageId"))
  end
  receipt = Base.findfirst("./eb:SignalMessage/eb:Receipt", messaging, RNS)
  if receipt !== nothing
    digests = [attr(r, "URI") => text(r, "./ds:DigestValue")
               for r in Base.findall(".//ebbp:NonRepudiationInformation//ds:Reference", receipt, RNS)]
    return Receipt(message_id=info("MessageId"), ref_to_message_id=info("RefToMessageId"), digests=digests)
  end
  throw(TransportError("unrecognised ebMS signal"))
end

"The digests we signed, `reference URI => DigestValue`, from a secured envelope."
sent_digests(doc::Document) = Dict(
  r["URI"] => text(r, "./ds:DigestValue")
  for r in Base.findall("//ds:Signature/ds:SignedInfo/ds:Reference", root(doc), RNS))

"""
Does the receipt's NonRepudiationInformation agree with what we sent?

The receipt is the non-repudiation record — it is the ATO restating the digests
of the message it accepted. Unchecked, it records only that *something* came
back. True means every digest the receipt reports is one we signed (gateways
differ in how many they echo, so this does not demand full coverage) and that
it reports at least one. A receipt carrying no NRI at all can't corroborate
anything, so it is false.
"""
receipt_covers(r::Receipt, doc::Document) = begin
  isempty(r.digests) && return false
  sent = sent_digests(doc)
  all(((uri, dv),) -> get(sent, uri, nothing) == dv, r.digests)
end

# ── transport + MEPs ──────────────────────────────────────────────────────────

"""
POST raw bytes. Returns `(status, headers::Dict, body)`. Header names lowercased.
Connection-level failures become `TransportError`. TLS 1.3 comes from libcurl/OpenSSL.
"""
post(url::AbstractString, body::Vector{UInt8}, content_type::AbstractString; timeout=300) = begin
  out = IOBuffer()
  resp = try
    Downloads.request(url; method="POST", input=IOBuffer(body), output=out,
      headers=["Content-Type" => content_type], timeout=timeout, throw=true)
  catch e
    e isa Downloads.RequestError ? throw(TransportError("$(e.message) ($(e.code)) for $url")) : rethrow()
  end
  resp.status, Dict(lowercase(k) => v for (k, v) in resp.headers), take!(out)
end

"Assemble the final wire message: bare SOAP when there are no attachments, else SOAP root part + gzipped attachment parts."
wire(doc::Document, attachments) = begin
  isempty(attachments) && return Vector{UInt8}(string(doc)), "application/soap+xml; charset=UTF-8"
  parts = [MimePart("application/soap+xml; charset=UTF-8", Vector{UInt8}(string(doc)); id="root@$(MESSAGE_ID_DOMAIN[])");
           [MimePart("application/gzip", bytes; id=cid, headers=["Content-Transfer-Encoding" => "binary"])
            for (cid, bytes) in attachments]]
  mime_encode(parts)
end

"A selective PullRequest signal envelope (SBR profile: RefToMessageId inside eb:PullRequest)."
pull_envelope(ref::AbstractString; timestamp=now(UTC)) = parsexml(
  """<s:Envelope xmlns:s="$S12" xmlns:eb="$EB" xmlns:wsu="$WSU"><s:Header>""" *
  """<eb:Messaging wsu:Id="ebmessaging" s:mustUnderstand="true"><eb:SignalMessage>""" *
  """<eb:MessageInfo><eb:Timestamp>$(format(timestamp, TSFORMAT))</eb:Timestamp>""" *
  """<eb:MessageId>$(newid())</eb:MessageId></eb:MessageInfo>""" *
  """<eb:PullRequest><eb:RefToMessageId>$(xmlescape(ref))</eb:RefToMessageId></eb:PullRequest>""" *
  """</eb:SignalMessage></eb:Messaging></s:Header><s:Body wsu:Id="soapbody"/></s:Envelope>""")

"Base delay for the exchange retry backoff; doubles each attempt."
const RETRY_BACKOFF = Ref(0.5)

# Gateway / reverse-proxy shedding: the request never reached the MSH. Retry
# with the same MessageId (reception awareness). HTTP 500 is *not* here —
# ebMS3 error signals commonly ride a 500 and must be parsed, not retried.
retryable_status(status::Integer) = status == 502 || status == 503 || status == 504

"""
POST with connection-failure and 502/503/504 retries. Returns
`(status, headers, body)` like `post`. Used by both the MSH path and STS
token issuance so behaviour stays consistent.
"""
post_with_retry(url, body, content_type; retries=2) = begin
  attempt = 0
  while true
    try
      status, headers, rbody = post(url, body, content_type)
      if retryable_status(status) && attempt < retries
        attempt += 1
        sleep(RETRY_BACKOFF[] * 2.0^(attempt - 1))
        continue
      end
      return status, headers, rbody
    catch e
      (e isa TransportError && attempt < retries) || rethrow()
      attempt += 1
      # An immediate resend hits whatever knocked the first one over; a gateway
      # shedding load reads three in a row as three messages.
      sleep(RETRY_BACKOFF[] * 2.0^(attempt - 1))
    end
  end
end

"""
Parse the SOAP root of a response and optionally verify its signature with a
pinned certificate. Multipart attachments are passed through to `verify` for
cid: references. Throws `TransportError` when the signature is missing or fails.

Only call this when the peer is known to sign responses — ATO EVTE business
payloads often ride TLS alone and leave `response_cert` unset.
"""
check_response_signature(body::Vector{UInt8}, content_type::AbstractString;
                         cert, require=nothing) = begin
  parts = try
    occursin("multipart/related", content_type) ? mime_parse(body, content_type) :
            [MimePart(String(content_type), body)]
  catch e
    throw(TransportError("cannot verify response: unreadable body — $(sprint(showerror, e))"))
  end
  isempty(parts) && throw(TransportError("cannot verify response: empty body"))
  doc = try
    parsexml(parts[1].bytes)
  catch e
    throw(TransportError("cannot verify response: not XML — $(snippet(parts[1].bytes))"))
  end
  atts = Dict(p.id => p.bytes for p in parts[2:end])
  ok = try
    verify(doc; cert=cert, attachments=atts, require=require)
  catch e
    throw(TransportError("inbound response signature check failed — $(sprint(showerror, e))"))
  end
  ok || throw(TransportError("inbound response signature failed verification"))
  doc
end

"POST a secured doc and parse the reply. Transport failures and gateway 502/503/504 retry with the SAME message bytes (reception awareness — the server dedups on MessageId)."
exchange(url, doc, attachments; retries=2, response_cert=nothing, response_require=nothing) = begin
  body, ctype = wire(doc, attachments)
  status, headers, rbody = post_with_retry(url, body, ctype; retries=retries)
  rctype = get(headers, "content-type", "application/soap+xml")
  response_cert === nothing ||
    check_response_signature(rbody, rctype; cert=response_cert, require=response_require)
  parse_response(rbody, rctype; status=status)
end

"""
One-Way/Push: send a UserMessage, expect a Receipt (or an EbMSError).

When the receipt carries NonRepudiationInformation digests, they are checked
against the message we just signed (`receipt_covers`). Empty NRI is accepted —
some gateways omit it. Pass `verify_receipt=false` to skip the check.

`response_cert` (DER) optionally verifies the inbound SOAP signature with a
pinned peer certificate before the receipt is returned. Leave it `nothing`
unless the peer is known to sign responses.
"""
push(url, msg::UserMessage; cred, assertion=nothing, retries=2, verify_receipt=true,
     response_cert=nothing, response_require=nothing) = begin
  doc, atts = envelope(msg)
  secure!(doc, atts, cred, assertion)
  r = exchange(url, doc, atts; retries=retries, response_cert=response_cert,
               response_require=response_require)
  if verify_receipt && r isa Receipt && !isempty(r.digests) && !receipt_covers(r, doc)
    throw(TransportError(
      "receipt NonRepudiationInformation digests do not match the message we sent"))
  end
  r
end

"""
One-Way/Selective-Pull: ask for the response to `ref`. Returns the pulled
`UserMessage`, or `nothing` when the channel is empty (EBMS:0006 — keep polling).
"""
pull(url, ref::AbstractString; cred, assertion=nothing, retries=2,
     response_cert=nothing, response_require=nothing) = begin
  doc = pull_envelope(ref)
  secure!(doc, [], cred, assertion)
  r = exchange(url, doc, []; retries=retries, response_cert=response_cert,
               response_require=response_require)
  r isa EbMSError && isempty_mpc(r) ? nothing : r
end

"Two-Way/Sync: send a UserMessage, expect the business response in the same HTTP exchange."
sync_call(url, msg::UserMessage; cred, assertion=nothing, retries=2, kwargs...) =
  push(url, msg; cred=cred, assertion=assertion, retries=retries, kwargs...)
