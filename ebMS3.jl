@use "github.com/jkroso/Prospects.jl" @struct
@use "./XMLSig.jl" DS WSSE WSU S12 EB SAML2
@use EzXML: parsexml, root, Document
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
