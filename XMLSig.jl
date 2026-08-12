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
libxml2's `xmlFree` is a function *pointer variable*, not a function, so it
can't be ccall'd by name — the symbol's address is the variable, not the code.
Buffers handed back by `xmlC14NDocDumpMemory` must go back through it.
"""
const XMLFREE = Ref{Ptr{Cvoid}}(C_NULL)
xmlfree(p::Ptr) = begin
  p == C_NULL && return
  XMLFREE[] == C_NULL && (XMLFREE[] = unsafe_load(cglobal((:xmlFree, libxml2), Ptr{Cvoid})))
  ccall(XMLFREE[], Cvoid, (Ptr{Cvoid},), p)
end

"""
Evaluate `expr` and hand the resulting node set to `f`, freeing the XPath
context and object afterwards. `context`, when given, is the node the
expression is evaluated relative to. The node set dies with the object, so `f`
must consume it before returning.
"""
with_nodeset(f, doc::Document, expr::AbstractString, prefixes, context=nothing) = begin
  ctx = ccall((:xmlXPathNewContext, libxml2), Ptr{Cvoid}, (Ptr{Cvoid},), doc.node.ptr)
  ctx == C_NULL && error("xmlXPathNewContext failed")
  try
    for (p, ns) in prefixes
      ccall((:xmlXPathRegisterNs, libxml2), Cint, (Ptr{Cvoid}, Cstring, Cstring), ctx, p, ns)
    end
    obj = context === nothing ?
      ccall((:xmlXPathEvalExpression, libxml2), Ptr{Cvoid}, (Cstring, Ptr{Cvoid}), expr, ctx) :
      ccall((:xmlXPathNodeEval, libxml2), Ptr{Cvoid}, (Ptr{Cvoid}, Cstring, Ptr{Cvoid}), context.ptr, expr, ctx)
    obj == C_NULL && error("xpath eval failed: $expr")
    try
      # struct _xmlXPathObject { xmlXPathObjectType type; xmlNodeSetPtr nodesetval; … }
      f(unsafe_load(Ptr{Ptr{Cvoid}}(obj + 8)))
    finally
      ccall((:xmlXPathFreeObject, libxml2), Cvoid, (Ptr{Cvoid},), obj)
    end
  finally
    ccall((:xmlXPathFreeContext, libxml2), Cvoid, (Ptr{Cvoid},), ctx)
  end
end

"struct _xmlNodeSet { int nodeNr; … } — how many nodes an expression selected."
nodeset_length(ns::Ptr{Cvoid}) = ns == C_NULL ? 0 : Int(unsafe_load(Ptr{Cint}(ns)))

dump_c14n(doc::Document, nodeset::Ptr{Cvoid}, exclusive, comments, inclusive_prefixes) = begin
  out = Ref{Ptr{UInt8}}(C_NULL)
  # null-terminated xmlChar** of InclusiveNamespaces PrefixList entries
  incl = String.(inclusive_prefixes)  # SubStrings aren't NUL-terminated
  plist = isempty(incl) ? C_NULL : [[pointer(p) for p in incl]; Ptr{UInt8}(C_NULL)]
  n = GC.@preserve incl ccall((:xmlC14NDocDumpMemory, libxml2), Cint,
    (Ptr{Cvoid}, Ptr{Cvoid}, Cint, Ptr{Ptr{UInt8}}, Cint, Ptr{Ptr{UInt8}}),
    doc.node.ptr, nodeset, exclusive ? 1 : 0, plist, comments ? 1 : 0, out)
  n < 0 && (xmlfree(out[]); error("c14n failed ($n)"))
  try unsafe_string(out[], n) finally xmlfree(out[]) end
end

"""
Exclusive C14N 1.0 (no comments) of a whole document, or of the subtree selected
by `xpath` (e.g. `//ds:SignedInfo` or `//*[@wsu:Id="body"]`) canonicalized in
document context.
"""
c14n(doc::Document, xpath=nothing; exclusive=true, comments=false, prefixes=PREFIXES, inclusive_prefixes=String[]) = begin
  xpath === nothing && return dump_c14n(doc, C_NULL, exclusive, comments, inclusive_prefixes)
  startswith(xpath, "//") || error("xpath must start with // : $xpath")
  expr = "(//. | //@* | //namespace::*)[ancestor-or-self::$(xpath[3:end])]"
  with_nodeset(doc, expr, prefixes) do ns
    dump_c14n(doc, ns, exclusive, comments, inclusive_prefixes)
  end
end

# Everything under the context node: the node itself, its descendants, and their
# attribute and namespace nodes — the same selection `ancestor-or-self` makes,
# but anchored to one node rather than to whatever an xpath happens to match.
const SUBTREE = "descendant-or-self::node() | descendant-or-self::*/@* | descendant-or-self::*/namespace::*"

"""
Exclusive C14N of exactly this node's subtree, in its document's context.
Prefer this to an `//xpath` when you hold the node: an xpath silently
canonicalizes *every* match, so `//ds:SignedInfo` in a two-signature document
returns the wrong one.
"""
c14n(node::Node; exclusive=true, comments=false, prefixes=PREFIXES, inclusive_prefixes=String[]) = begin
  doc = document(node)
  with_nodeset(doc, SUBTREE, prefixes, node) do ns
    dump_c14n(doc, ns, exclusive, comments, inclusive_prefixes)
  end
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
      ctx, C_NULL, len, data, length(data)) == 1 || error("DigestSign (size query) failed")
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

"""
An XPath 1.0 string literal holding arbitrary text. The language has no escape
syntax, so a value containing both quote characters has to be reassembled with
`concat()`. Reference URIs in a document we did not write are attacker-supplied
and reach `byid` — without this they would splice into the expression.
"""
xpath_literal(s::AbstractString) = occursin('"', s) ?
  "concat(" * join(("\"$p\"" for p in split(s, '"')), ", '\"', ") * ")" : "\"$s\""

byid(id) = (lit = xpath_literal(id); "//*[@wsu:Id=$lit or @Id=$lit or @ID=$lit]")

"How many elements carry `id` as an Id/ID/wsu:Id attribute."
count_id(doc::Document, id::AbstractString) =
  with_nodeset(nodeset_length, doc, byid(id), PREFIXES)

"""
A ds:Reference must resolve to exactly one element. Zero means the digest would
be taken over an empty node set — a signature that looks valid and covers
nothing. More than one means it covers their concatenation, which is not what
the URI says.
"""
check_id(doc::Document, id::AbstractString) = begin
  n = count_id(doc, id)
  n == 1 || error("cannot reference #$id: it matches $n elements, expected exactly 1")
end

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
    check_id(doc, id)  # refuse to sign a reference that resolves to nothing
    dv = base64encode(sha256(Vector{UInt8}(c14n(doc, byid(id)))))
    """<ds:Reference URI="#$id"><ds:Transforms><ds:Transform Algorithm="$EXC_C14N"/></ds:Transforms><ds:DigestMethod Algorithm="$SHA256_URI"/><ds:DigestValue>$dv</ds:DigestValue></ds:Reference>"""
  end
  for (cid, bytes) in attachments  # ordered pairs preferred: a Dict loses wire order
    dv = base64encode(sha256(bytes))
    push!(refs, """<ds:Reference URI="cid:$cid"><ds:Transforms><ds:Transform Algorithm="$SWA_TRANSFORM"/></ds:Transforms><ds:DigestMethod Algorithm="$SHA256_URI"/><ds:DigestValue>$dv</ds:DigestValue></ds:Reference>""")
  end
  signedinfo = """<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="$EXC_C14N"/><ds:SignatureMethod Algorithm="$RSA_SHA256"/>$(join(refs))</ds:SignedInfo>"""
  ki = keyinfo == :x509data ?
    """<ds:KeyInfo><ds:X509Data><ds:X509Certificate>$(base64encode(pair.cert_der))</ds:X509Certificate></ds:X509Data></ds:KeyInfo>""" :
    keyinfo
  template = parsexml("""<ds:Signature xmlns:ds="$DS">$signedinfo<ds:SignatureValue></ds:SignatureValue>$ki</ds:Signature>""")
  signode = graft!(parent, root(template))
  # This signature's own SignedInfo — not `//ds:SignedInfo`, which would pick an
  # earlier signature's (an STS-signed assertion, a second sign! call) and
  # produce a SignatureValue over the wrong bytes.
  si = c14n(Base.findfirst("./ds:SignedInfo", signode, ["ds"=>DS]))
  sv = base64encode(rsa_sign(pair.key, Vector{UInt8}(si)))
  Base.findfirst("./ds:SignatureValue", signode, ["ds"=>DS]).content = sv
  signode
end

# ── verification ──────────────────────────────────────────────────────────────

const NS = ["ds"=>DS, "wsse"=>WSSE, "wsu"=>WSU, "s"=>S12]

digestbytes(alg, bytes) = alg == SHA256_URI ? sha256(bytes) :
                          alg == SHA1_URI   ? sha1(bytes) :
                          error("unsupported digest $alg")

"Attachments may be given as ordered pairs (wire order) or as a Dict."
atts_dict(a) = a isa AbstractDict ? a : Dict{String,Vector{UInt8}}(a)

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
    # Zero matches would digest an empty node set; several would digest their
    # concatenation. Either way the URI does not mean what it says.
    count_id(doc, id) == 1 ?
      Vector{UInt8}(c14n(doc, byid(id); exclusive=exc, inclusive_prefixes=plist)) : nothing
  else
    nothing  # external references unsupported
  end
  bytes !== nothing && digestbytes(dalg, bytes) == expected
end

"The URIs the first ds:Signature in `doc` claims to cover, in document order."
signed_uris(doc::Document) = begin
  sig = Base.findfirst("//ds:Signature", root(doc), NS)
  sig === nothing ? String[] : [r["URI"] for r in Base.findall("./ds:SignedInfo/ds:Reference", sig, NS)]
end

"""
Verify the first ds:Signature in `doc`: every reference digest plus the
SignedInfo signature. Key comes from `cert` (DER bytes) or, failing that, the
embedded KeyInfo X509Certificate / wsse:BinarySecurityToken.

!!! warning "This is a signature check, not an authorization decision"
    A true result means *some* key signed *the elements this signature names*.
    It does not say the key is trusted — with `cert=nothing` the certificate
    comes from the document itself, so an attacker's own key passes — and it
    does not say the signature covers the data you are about to act on. An
    attacker who holds any signed fragment can leave it intact and put their
    content elsewhere in the tree (XML signature wrapping); every digest still
    matches. To rely on a signature you must pass a `cert` you pinned out of
    band **and** name, in `require`, the wsu:Id of every element whose content
    you will read.
"""
function verify(doc::Document; cert=nothing, attachments=Dict{String,Vector{UInt8}}(), require=nothing)
  sig = Base.findfirst("//ds:Signature", root(doc), NS)
  sig === nothing && error("no ds:Signature in document")
  sinode = Base.findfirst("./ds:SignedInfo", sig, NS)
  sinode === nothing && error("ds:Signature has no ds:SignedInfo")
  refs = Base.findall("./ds:Reference", sinode, NS)
  isempty(refs) && return false  # signs nothing; `all` over none would say true
  if require !== nothing
    uris = Set(r["URI"] for r in refs)
    all(id -> (startswith(id, "#") ? id : "#$id") in uris, require) || return false
  end
  atts = atts_dict(attachments)
  all(r -> checkref(doc, r, atts), refs) || return false
  cm = Base.findfirst("./ds:CanonicalizationMethod", sinode, NS)
  si = c14n(sinode; exclusive=cm["Algorithm"] == EXC_C14N, inclusive_prefixes=prefixlist(cm))
  salg = Base.findfirst("./ds:SignatureMethod", sinode, NS)["Algorithm"]
  md = salg == RSA_SHA256 ? :sha256 : salg == RSA_SHA1 ? :sha1 : error("unsupported signature $salg")
  sv = b64bytes(Base.findfirst("./ds:SignatureValue", sig, NS).content)
  cert_der = cert !== nothing ? cert : begin
    emb = Base.findfirst(".//ds:X509Certificate", sig, NS)
    emb === nothing && (emb = Base.findfirst("//wsse:BinarySecurityToken", root(doc), NS))
    emb === nothing && error("no certificate available to verify with")
    b64bytes(emb.content)
  end
  rsa_verify(cert_der, Vector{UInt8}(si), sv; md=md)
end
