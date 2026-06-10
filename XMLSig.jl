@use EzXML: parsexml, Document, Node, root, libxml2, document, unlink!, _Node
@use OpenSSL: EvpPKey, libcrypto
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
c14n(doc::Document, xpath=nothing; exclusive=true, comments=false, prefixes=PREFIXES, inclusive_prefixes=String[]) = begin
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
  # null-terminated xmlChar** of InclusiveNamespaces PrefixList entries
  inclusive_prefixes = String.(inclusive_prefixes)  # SubStrings aren't NUL-terminated
  plist = isempty(inclusive_prefixes) ? C_NULL :
    [[pointer(p) for p in inclusive_prefixes]; Ptr{UInt8}(C_NULL)]
  n = GC.@preserve inclusive_prefixes ccall((:xmlC14NDocDumpMemory, libxml2), Cint,
    (Ptr{Cvoid}, Ptr{Cvoid}, Cint, Ptr{Ptr{UInt8}}, Cint, Ptr{Ptr{UInt8}}),
    doc.node.ptr, nodeset, exclusive ? 1 : 0, plist, comments ? 1 : 0, out)
  n < 0 && error("c14n failed ($n)")
  unsafe_string(out[], n)
end

"PrefixList tokens of an InclusiveNamespaces child, if any."
prefixlist(node::Node) = begin
  inc = Base.findfirst(".//*[local-name()='InclusiveNamespaces']", node)
  inc === nothing ? String[] : split(inc["PrefixList"])
end

# ── crypto primitives (libcrypto ccalls, proven by spike 2026-06-10) ──────────

evp_md(alg::Symbol) = alg == :sha256 ? ccall((:EVP_sha256, libcrypto), Ptr{Cvoid}, ()) :
                      alg == :sha1   ? ccall((:EVP_sha1, libcrypto), Ptr{Cvoid}, ()) :
                      error("unsupported digest $alg")

rsa_sign(key::EvpPKey, data::Vector{UInt8}; md=:sha256) = begin
  ctx = ccall((:EVP_MD_CTX_new, libcrypto), Ptr{Cvoid}, ())
  try
    ccall((:EVP_DigestSignInit, libcrypto), Cint,
      (Ptr{Cvoid}, Ptr{Ptr{Cvoid}}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
      ctx, C_NULL, evp_md(md), C_NULL, key.evp_pkey) == 1 || error("DigestSignInit failed")
    len = Ref{Csize_t}(0)
    ccall((:EVP_DigestSign, libcrypto), Cint,
      (Ptr{Cvoid}, Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t),
      ctx, C_NULL, len, data, length(data))
    sig = Vector{UInt8}(undef, len[])
    ccall((:EVP_DigestSign, libcrypto), Cint,
      (Ptr{Cvoid}, Ptr{UInt8}, Ptr{Csize_t}, Ptr{UInt8}, Csize_t),
      ctx, sig, len, data, length(data)) == 1 || error("DigestSign failed")
    resize!(sig, len[])
  finally
    ccall((:EVP_MD_CTX_free, libcrypto), Cvoid, (Ptr{Cvoid},), ctx)
  end
end

"Public key from a DER certificate."
cert_pubkey(cert_der::Vector{UInt8}) = begin
  pp = Ref{Ptr{UInt8}}(pointer(cert_der))
  x509 = GC.@preserve cert_der ccall((:d2i_X509, libcrypto), Ptr{Cvoid},
    (Ptr{Cvoid}, Ptr{Ptr{UInt8}}, Clong), C_NULL, pp, length(cert_der))
  x509 == C_NULL && error("d2i_X509 failed: not a DER certificate")
  pkey = ccall((:X509_get_pubkey, libcrypto), Ptr{Cvoid}, (Ptr{Cvoid},), x509)
  ccall((:X509_free, libcrypto), Cvoid, (Ptr{Cvoid},), x509)
  pkey == C_NULL && error("X509_get_pubkey failed")
  pkey
end

rsa_verify(cert_der::Vector{UInt8}, data::Vector{UInt8}, sig::Vector{UInt8}; md=:sha256) = begin
  pkey = cert_pubkey(cert_der)
  ctx = ccall((:EVP_MD_CTX_new, libcrypto), Ptr{Cvoid}, ())
  try
    ccall((:EVP_DigestVerifyInit, libcrypto), Cint,
      (Ptr{Cvoid}, Ptr{Ptr{Cvoid}}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
      ctx, C_NULL, evp_md(md), C_NULL, pkey) == 1 || error("DigestVerifyInit failed")
    ccall((:EVP_DigestVerify, libcrypto), Cint,
      (Ptr{Cvoid}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t),
      ctx, sig, length(sig), data, length(data)) == 1
  finally
    ccall((:EVP_MD_CTX_free, libcrypto), Cvoid, (Ptr{Cvoid},), ctx)
    ccall((:EVP_PKEY_free, libcrypto), Cvoid, (Ptr{Cvoid},), pkey)
  end
end

pem_to_der(pem::AbstractString) = begin
  m = match(r"-----BEGIN [A-Z0-9 ]+-----(.*?)-----END"s, pem)
  m === nothing && error("no PEM block found")
  base64decode(replace(m[1], r"\s" => ""))
end

"PEM key + cert files → (key=EvpPKey, cert_der=bytes), the shape sign! expects."
load_pem_keypair(keypath, certpath) =
  (key=EvpPKey(read(keypath, String)), cert_der=pem_to_der(read(certpath, String)))

b64bytes(s::AbstractString) = base64decode(replace(s, r"\s" => ""))

# ── signing ───────────────────────────────────────────────────────────────────

byid(id) = """//*[@wsu:Id="$id" or @Id="$id" or @ID="$id"]"""

"Copy `source` (from another document) and append it under `parent`."
graft!(parent::Node, source::Node) = begin
  docptr = document(parent).node.ptr
  copied = ccall((:xmlDocCopyNode, libxml2), Ptr{_Node}, (Ptr{Cvoid}, Ptr{Cvoid}, Cint), source.ptr, docptr, 1)
  copied == C_NULL && error("xmlDocCopyNode failed")
  added = ccall((:xmlAddChild, libxml2), Ptr{_Node}, (Ptr{Cvoid}, Ptr{_Node}), parent.ptr, copied)
  added == C_NULL && error("xmlAddChild failed")
  Node(added)
end

"""
Build a ds:Signature over the elements with the given wsu:Id values (exclusive
c14n + RSA-SHA256) plus any `attachments` (cid => raw octets, digested via the
WS-Security SwA content transform), attach it under `parent`, sign, and return it.

`keyinfo`: `:x509data` embeds the cert; or pass a prebuilt KeyInfo XML string
(e.g. a wsse:SecurityTokenReference).
"""
sign!(doc::Document, parent::Node, ids::Vector{String}, pair;
      attachments=Dict{String,Vector{UInt8}}(), keyinfo=:x509data) = begin
  refs = map(ids) do id
    dv = base64encode(sha256(Vector{UInt8}(c14n(doc, byid(id)))))
    """<ds:Reference URI="#$id"><ds:Transforms><ds:Transform Algorithm="$EXC_C14N"/></ds:Transforms><ds:DigestMethod Algorithm="$SHA256_URI"/><ds:DigestValue>$dv</ds:DigestValue></ds:Reference>"""
  end
  for (cid, bytes) in attachments
    dv = base64encode(sha256(bytes))
    push!(refs, """<ds:Reference URI="cid:$cid"><ds:Transforms><ds:Transform Algorithm="$SWA_TRANSFORM"/></ds:Transforms><ds:DigestMethod Algorithm="$SHA256_URI"/><ds:DigestValue>$dv</ds:DigestValue></ds:Reference>""")
  end
  signedinfo = """<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="$EXC_C14N"/><ds:SignatureMethod Algorithm="$RSA_SHA256"/>$(join(refs))</ds:SignedInfo>"""
  ki = keyinfo == :x509data ?
    """<ds:KeyInfo><ds:X509Data><ds:X509Certificate>$(base64encode(pair.cert_der))</ds:X509Certificate></ds:X509Data></ds:KeyInfo>""" :
    keyinfo
  template = parsexml("""<ds:Signature xmlns:ds="$DS">$signedinfo<ds:SignatureValue></ds:SignatureValue>$ki</ds:Signature>""")
  signode = graft!(parent, root(template))
  si = c14n(doc, "//ds:SignedInfo")
  sv = base64encode(rsa_sign(pair.key, Vector{UInt8}(si)))
  Base.findfirst("./ds:SignatureValue", signode, ["ds"=>DS]).content = sv
  signode
end

# ── verification ──────────────────────────────────────────────────────────────

const NS = ["ds"=>DS, "wsse"=>WSSE, "wsu"=>WSU, "s"=>S12]

digestbytes(alg, bytes) = alg == SHA256_URI ? sha256(bytes) :
                          alg == SHA1_URI   ? sha1(bytes) :
                          error("unsupported digest $alg")

"Re-compute one ds:Reference and compare digests."
function checkref(doc::Document, ref::Node, attachments)
  uri = ref["URI"]
  tnodes = Base.findall(".//ds:Transform", ref, NS)
  transforms = [t["Algorithm"] for t in tnodes]
  plist = isempty(tnodes) ? String[] : reduce(vcat, prefixlist.(tnodes))
  dalg = Base.findfirst(".//ds:DigestMethod", ref, NS)["Algorithm"]
  expected = b64bytes(Base.findfirst(".//ds:DigestValue", ref, NS).content)
  exc = EXC_C14N in transforms
  id = startswith(uri, "#") ? replace(uri[2:end], r"^xpointer\(id\('(.*)'\)\)$" => s"\1") : ""
  bytes = if startswith(uri, "cid:")
    get(attachments, uri[5:end], nothing)
  elseif uri == ""
    copy_ = parsexml(string(doc))
    if ENVELOPED in transforms
      sig = Base.findfirst("//ds:Signature", root(copy_), NS)
      sig === nothing || unlink!(sig)
    end
    Vector{UInt8}(c14n(copy_; exclusive=exc, inclusive_prefixes=plist))
  elseif startswith(uri, "#")
    Vector{UInt8}(c14n(doc, byid(id); exclusive=exc, inclusive_prefixes=plist))
  else
    nothing  # external references unsupported
  end
  bytes !== nothing && digestbytes(dalg, bytes) == expected
end

"""
Verify the first ds:Signature in `doc`: every reference digest plus the
SignedInfo signature. Key comes from `cert` (DER bytes) or, failing that, the
embedded KeyInfo X509Certificate / wsse:BinarySecurityToken.
"""
function verify(doc::Document; cert=nothing, attachments=Dict{String,Vector{UInt8}}())
  sig = Base.findfirst("//ds:Signature", root(doc), NS)
  sig === nothing && error("no ds:Signature in document")
  all(r -> checkref(doc, r, attachments), Base.findall(".//ds:Reference", sig, NS)) || return false
  cm = Base.findfirst(".//ds:CanonicalizationMethod", sig, NS)
  si = c14n(doc, "//ds:SignedInfo"; exclusive=cm["Algorithm"] == EXC_C14N, inclusive_prefixes=prefixlist(cm))
  salg = Base.findfirst(".//ds:SignatureMethod", sig, NS)["Algorithm"]
  md = salg == RSA_SHA256 ? :sha256 : salg == RSA_SHA1 ? :sha1 : error("unsupported signature $salg")
  sv = b64bytes(Base.findfirst(".//ds:SignatureValue", sig, NS).content)
  cert_der = cert !== nothing ? cert : begin
    emb = Base.findfirst(".//ds:X509Certificate", sig, NS)
    emb === nothing && (emb = Base.findfirst("//wsse:BinarySecurityToken", root(doc), NS))
    emb === nothing && error("no certificate available to verify with")
    b64bytes(emb.content)
  end
  rsa_verify(cert_der, Vector{UInt8}(si), sv; md=md)
end
