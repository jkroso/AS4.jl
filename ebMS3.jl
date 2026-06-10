@use "github.com/jkroso/Prospects.jl" @struct
@use "./XMLSig.jl" DS WSSE WSU S12 EB SAML2
@use "./MIME.jl" MimePart mime_parse
@use EzXML: parsexml, root, Document, Node
@use CodecZlib: GzipCompressor, GzipDecompressor
@use UUIDs: uuid4
@use Dates: now, UTC, format, @dateformat_str

const TSFORMAT = dateformat"yyyy-mm-dd\THH:MM:SS.sss\Z"

xmlescape(s) = replace(string(s), '&'=>"&amp;", '<'=>"&lt;", '>'=>"&gt;", '"'=>"&quot;")

"One business payload: raw bytes plus the ebMS PartProperties that describe them."
@struct struct Part
  bytes::Vector{UInt8}
  name::String = ""          # PartProperty DocumentName, e.g. "PAYEVNT"
  doctype::String = ""       # PartProperty DocumentType: BASE | SCHEDULE
  mime::String = "text/xml"  # of the *uncompressed* document
  cid::String = "$(uuid4())@as4"
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
  message_id::String = "$(uuid4())@as4.centient"
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

parse_party(node, tag) = begin
  pid = Base.findfirst("./eb:PartyInfo/eb:$tag/eb:PartyId", node, RNS)
  role = text(node, "./eb:PartyInfo/eb:$tag/eb:Role")
  pid === nothing ? ("", "", role) : (pid.content, something(pid["type"], ""), role)
end

parse_usermessage(um::Node, attachments::Dict{String,Vector{UInt8}}) = begin
  parts = Part[]
  for pi in Base.findall("./eb:PayloadInfo/eb:PartInfo", um, RNS)
    href = something(pi["href"], "")
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

"""
Parse a response body into a `Receipt`, `EbMSError`, or `UserMessage`.
Throws `TransportError` for SOAP faults without an ebMS Messaging header.
"""
parse_response(body::Vector{UInt8}, content_type::AbstractString) = begin
  parts = occursin("multipart/related", content_type) ? mime_parse(body, content_type) :
          [MimePart(String(content_type), body)]
  isempty(parts) && throw(TransportError("empty response body"))
  doc = parsexml(parts[1].bytes)
  attachments = Dict(p.id => p.bytes for p in parts[2:end])
  messaging = Base.findfirst("//eb:Messaging", root(doc), RNS)
  if messaging === nothing
    reason = text(root(doc), "//s:Fault//s:Text")
    throw(TransportError(isempty(reason) ? "no eb:Messaging in response" : "SOAP fault: $reason"))
  end
  um = Base.findfirst("./eb:UserMessage", messaging, RNS)
  um === nothing || return parse_usermessage(um, attachments)
  info(x) = text(messaging, "./eb:SignalMessage/eb:MessageInfo/eb:$x")
  err = Base.findfirst("./eb:SignalMessage/eb:Error", messaging, RNS)
  if err !== nothing
    return EbMSError(something(err["errorCode"], ""), something(err["severity"], ""),
                     something(err["shortDescription"], ""), something(err["category"], ""),
                     text(err, "./eb:ErrorDetail"), info("RefToMessageId"))
  end
  receipt = Base.findfirst("./eb:SignalMessage/eb:Receipt", messaging, RNS)
  if receipt !== nothing
    digests = [something(r["URI"], "") => text(r, "./ds:DigestValue")
               for r in Base.findall(".//ebbp:NonRepudiationInformation//ds:Reference", receipt, RNS)]
    return Receipt(message_id=info("MessageId"), ref_to_message_id=info("RefToMessageId"), digests=digests)
  end
  throw(TransportError("unrecognised ebMS signal"))
end
