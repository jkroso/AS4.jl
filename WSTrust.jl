@use "github.com/jkroso/Prospects.jl" @struct
@use "./XMLSig.jl" sign! graft! DS WSSE WSU S12 SAML2
@use "./ebMS3.jl" TransportError post xmlescape X509V3 B64ENC
@use EzXML: parsexml, root, Document, Node
@use Dates: DateTime, now, UTC, Minute, format, @dateformat_str
@use UUIDs: uuid4
@use Base64: base64encode, base64decode

const WST = "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
const WSA = "http://www.w3.org/2005/08/addressing"
const IDENTITY = "http://schemas.xmlsoap.org/ws/2005/05/identity"
const SAMLV2 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0"
const TS = dateformat"yyyy-mm-dd\THH:MM:SS.sss\Z"

# WIG §6.2 Figure 24 — the claim set the STS fills into the assertion
const CLAIMS = [
  ("http://vanguard.ebusiness.gov.au/2008/06/identity/claims/abn", false),
  ("http://vanguard.ebusiness.gov.au/2008/06/identity/claims/commonname", false),
  ("http://vanguard.ebusiness.gov.au/2008/06/identity/claims/credentialtype", false),
  ("http://vanguard.ebusiness.gov.au/2008/06/identity/claims/samlsubjectid", false),
  ("http://vanguard.ebusiness.gov.au/2008/06/identity/claims/fingerprint", false),
  ("http://vanguard.ebusiness.gov.au/2008/06/identity/claims/sbr_personid", true),
  ("http://vanguard.ebusiness.gov.au/2008/06/identity/claims/givennames", true),
  ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", true),
  ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", true),
  ("http://vanguard.ebusiness.gov.au/2008/06/identity/claims/credentialadministrator", true),
  ("http://vanguard.ebusiness.gov.au/2008/06/identity/claims/stalecrlminutes", true),
  ("http://vanguard.ebusiness.gov.au/2008/06/identity/claims/subjectdn", true),
  ("http://vanguard.ebusiness.gov.au/2008/06/identity/claims/issuerdn", true),
  ("http://vanguard.ebusiness.gov.au/2008/06/identity/claims/notafterdate", true),
  ("http://vanguard.ebusiness.gov.au/2008/06/identity/claims/certificateserialnumber", true),
  ("http://vanguard.ebusiness.gov.au/2008/06/identity/claims/previoussubject", true)]

"An STS-issued security token: the opaque encrypted SAML assertion + holder-of-key proof."
@struct struct Token
  assertion::Node              # saml2:EncryptedAssertion, never decrypted client-side
  proof_key::Vector{UInt8}     # session key — "included for future use" (WIG), kept anyway
  expires::DateTime
end

"A SOAP fault from the security token service."
struct STSFault <: Exception
  code::String
  reason::String
end
Base.showerror(io::IO, e::STSFault) = print(io, "STSFault $(e.code): $(e.reason)")

const TNS = ["s"=>S12, "wst"=>WST, "wsa"=>WSA, "wsu"=>WSU, "saml2"=>SAML2]

"""
Build the signed WS-Trust 1.3 RequestSecurityToken envelope (WIG §6.2 shape):
WS-Addressing headers, a wsu:Timestamp + BinarySecurityToken in wsse:Security,
Timestamp and wsa:To signed with the machine-credential key.
"""
rst(cred, sts_url, applies_to; created=now(UTC)) = begin
  claims = join("""<i:ClaimType Optional="$(opt)" Uri="$uri"/>""" for (uri, opt) in CLAIMS)
  xml = """<s:Envelope xmlns:s="$S12" xmlns:wsa="$WSA" xmlns:wsu="$WSU"><s:Header>""" *
    """<wsse:Security xmlns:wsse="$WSSE" s:mustUnderstand="true">""" *
    """<wsu:Timestamp wsu:Id="timestamp"><wsu:Created>$(format(created, TS))</wsu:Created><wsu:Expires>$(format(created + Minute(5), TS))</wsu:Expires></wsu:Timestamp>""" *
    """<wsse:BinarySecurityToken EncodingType="$B64ENC" ValueType="$X509V3" wsu:Id="signingCert">$(base64encode(cred.cert_der))</wsse:BinarySecurityToken>""" *
    """</wsse:Security>""" *
    """<wsa:To wsu:Id="msgto">$(xmlescape(sts_url))</wsa:To>""" *
    """<wsa:MessageID>urn:uuid:$(uuid4())</wsa:MessageID>""" *
    """<wsa:Action>$WST/RST/Issue</wsa:Action>""" *
    """</s:Header><s:Body>""" *
    """<wst:RequestSecurityToken xmlns:wst="$WST">""" *
    """<wst:RequestType>$WST/Issue</wst:RequestType>""" *
    """<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"><wsa:EndpointReference><wsa:Address>$(xmlescape(applies_to))</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>""" *
    """<wst:TokenType>$SAMLV2</wst:TokenType>""" *
    """<wst:Claims Dialect="$IDENTITY" xmlns:i="$IDENTITY">$claims</wst:Claims>""" *
    """<wst:Lifetime><wsu:Created>$(format(created, TS))</wsu:Created><wsu:Expires>$(format(created + Minute(30), TS))</wsu:Expires></wst:Lifetime>""" *
    """<wst:KeyType>$WST/SymmetricKey</wst:KeyType>""" *
    """<wst:KeySize>512</wst:KeySize>""" *
    """</wst:RequestSecurityToken></s:Body></s:Envelope>"""
  doc = parsexml(xml)
  sec = Base.findfirst("//*[local-name()='Security']", root(doc))
  str = """<ds:KeyInfo><wsse:SecurityTokenReference xmlns:wsse="$WSSE"><wsse:Reference URI="#signingCert" ValueType="$X509V3"/></wsse:SecurityTokenReference></ds:KeyInfo>"""
  sign!(doc, sec, ["timestamp", "msgto"], cred; keyinfo=str)
  doc
end

"Parse an RSTR(C) into a Token. SOAP faults raise STSFault."
parse_rstr(body::Vector{UInt8}) = begin
  doc = parsexml(body)
  fault = Base.findfirst("//s:Fault", root(doc), TNS)
  if fault !== nothing
    code = Base.findfirst(".//s:Value", fault, TNS)
    reason = Base.findfirst(".//s:Text", fault, TNS)
    throw(STSFault(code === nothing ? "" : code.content, reason === nothing ? "" : reason.content))
  end
  assertion = Base.findfirst("//saml2:EncryptedAssertion", root(doc), TNS)
  assertion === nothing && throw(TransportError("no EncryptedAssertion in STS response"))
  secret = Base.findfirst("//wst:RequestedProofToken/wst:BinarySecret", root(doc), TNS)
  expires = Base.findfirst("//wst:Lifetime/wsu:Expires", root(doc), TNS)
  Token(
    assertion=assertion,
    proof_key=secret === nothing ? UInt8[] : base64decode(replace(secret.content, r"\s" => "")),
    expires=expires === nothing ? now(UTC) + Minute(30) : DateTime(replace(strip(expires.content), "Z" => "")))
end

"""
Request a SAML token from the STS. One token covers all SBR services when
`applies_to` is the platform root (https://sbr.gov.au/services or the test.
variant) — the WIG-recommended scoping.
"""
issue_token(cred, sts_url, applies_to) = begin
  doc = rst(cred, sts_url, applies_to)
  ctype = """application/soap+xml; charset=utf-8; action="$WST/RST/Issue\""""
  _, _, body = post(sts_url, Vector{UInt8}(string(doc)), ctype)
  parse_rstr(body)
end

"Cache wrapper: refresh when within 5 minutes of expiry."
mutable struct TokenCache
  token::Union{Token,Nothing}
end
TokenCache() = TokenCache(nothing)

current_token(cache::TokenCache, cred, sts_url, applies_to) = begin
  t = cache.token
  (t === nothing || t.expires - now(UTC) < Minute(5)) && (cache.token = issue_token(cred, sts_url, applies_to))
  cache.token
end