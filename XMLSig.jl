@use EzXML: parsexml, Document, Node, root, libxml2
@use SHA: sha256, sha1
@use Base64: base64encode, base64decode

const DS = "http://www.w3.org/2000/09/xmldsig#"
const WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
const WSU = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
const S12 = "http://www.w3.org/2003/05/soap-envelope"
const EB = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
const SAML2 = "urn:oasis:names:tc:SAML:2.0:assertion"
const EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
const ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
const RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
const SHA256_URI = "http://www.w3.org/2001/04/xmlenc#sha256"
const SHA1_URI = "http://www.w3.org/2000/09/xmldsig#sha1"
const SWA_TRANSFORM = "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform"

const PREFIXES = Dict("ds"=>DS, "eb"=>EB, "wsse"=>WSSE, "wsu"=>WSU, "s"=>S12, "saml2"=>SAML2)

"""
Exclusive C14N 1.0 (no comments) of a whole document, or of the subtree selected
by `xpath` (e.g. `//ds:SignedInfo` or `//*[@wsu:Id="body"]`) canonicalized in
document context.
"""
c14n(doc::Document, xpath=nothing; prefixes=PREFIXES) = begin
  nodeset = C_NULL
  if xpath !== nothing
    ctx = ccall((:xmlXPathNewContext, libxml2), Ptr{Cvoid}, (Ptr{Cvoid},), doc.node.ptr)
    ctx == C_NULL && error("xmlXPathNewContext failed")
    for (p, ns) in prefixes
      ccall((:xmlXPathRegisterNs, libxml2), Cint, (Ptr{Cvoid}, Cstring, Cstring), ctx, p, ns)
    end
    startswith(xpath, "//") || error("xpath must start with // : $xpath")
    expr = "(//. | //@* | //namespace::*)[ancestor-or-self::$(xpath[3:end])]"
    obj = ccall((:xmlXPathEvalExpression, libxml2), Ptr{Cvoid}, (Cstring, Ptr{Cvoid}), expr, ctx)
    obj == C_NULL && error("xpath eval failed: $expr")
    # struct _xmlXPathObject { xmlXPathObjectType type; xmlNodeSetPtr nodesetval; … }
    nodeset = unsafe_load(Ptr{Ptr{Cvoid}}(obj + 8))
  end
  out = Ref{Ptr{UInt8}}(C_NULL)
  n = ccall((:xmlC14NDocDumpMemory, libxml2), Cint,
    (Ptr{Cvoid}, Ptr{Cvoid}, Cint, Ptr{Ptr{UInt8}}, Cint, Ptr{Ptr{UInt8}}),
    doc.node.ptr, nodeset, 1, C_NULL, 0, out)
  n < 0 && error("c14n failed ($n)")
  unsafe_string(out[], n)
end
