@use EzXML: parsexml, root
@use OpenSSL: libcrypto, EvpPKey, load_legacy_provider
@use Base64: base64decode

const CNS = ["c" => "http://auth.abr.gov.au/credential/xsd/SBRCredentialStore"]

"An ABR machine credential: identity fields + leaf cert + decrypted private key."
struct Credential
  id::String
  abn::String
  legal_name::String
  serial::String
  not_after::String
  cert_der::Vector{UInt8}
  chain::Vector{Vector{UInt8}}
  key::EvpPKey
end

b64(s) = base64decode(replace(s, r"\s" => ""))

"DER-encode an X509* handle."
x509_der(x::Ptr{Cvoid}) = begin
  len = ccall((:i2d_X509, libcrypto), Cint, (Ptr{Cvoid}, Ptr{Ptr{UInt8}}), x, C_NULL)
  buf = Vector{UInt8}(undef, len)
  pp = Ref{Ptr{UInt8}}(pointer(buf))
  GC.@preserve buf ccall((:i2d_X509, libcrypto), Cint, (Ptr{Cvoid}, Ptr{Ptr{UInt8}}), x, pp)
  buf
end

"Decimal serial number of an X509* handle."
x509_serial(x::Ptr{Cvoid}) = begin
  asn1 = ccall((:X509_get_serialNumber, libcrypto), Ptr{Cvoid}, (Ptr{Cvoid},), x)
  bn = ccall((:ASN1_INTEGER_to_BN, libcrypto), Ptr{Cvoid}, (Ptr{Cvoid}, Ptr{Cvoid}), asn1, C_NULL)
  s = ccall((:BN_bn2dec, libcrypto), Cstring, (Ptr{Cvoid},), bn)
  serial = unsafe_string(s)
  ccall((:BN_free, libcrypto), Cvoid, (Ptr{Cvoid},), bn)
  serial
end

"All certificates (DER) inside a PKCS#7/CMS blob."
cms_certs(der::Vector{UInt8}) = begin
  pp = Ref{Ptr{UInt8}}(pointer(der))
  cms = GC.@preserve der ccall((:d2i_CMS_ContentInfo, libcrypto), Ptr{Cvoid},
    (Ptr{Cvoid}, Ptr{Ptr{UInt8}}, Clong), C_NULL, pp, length(der))
  cms == C_NULL && error("publicCertificate is not a parseable PKCS#7/CMS blob")
  stack = ccall((:CMS_get1_certs, libcrypto), Ptr{Cvoid}, (Ptr{Cvoid},), cms)
  stack == C_NULL && error("no certificates in PKCS#7/CMS blob")
  n = ccall((:OPENSSL_sk_num, libcrypto), Cint, (Ptr{Cvoid},), stack)
  certs = map(0:n-1) do i
    x = ccall((:OPENSSL_sk_value, libcrypto), Ptr{Cvoid}, (Ptr{Cvoid}, Cint), stack, i)
    (der=x509_der(x), serial=x509_serial(x))
  end
  ccall((:CMS_ContentInfo_free, libcrypto), Cvoid, (Ptr{Cvoid},), cms)
  certs
end

"Decrypt an encrypted PKCS#8 EncryptedPrivateKeyInfo with a password."
decrypt_pkcs8(der::Vector{UInt8}, password::AbstractString) = begin
  attempt() = begin
    bio = ccall((:BIO_new_mem_buf, libcrypto), Ptr{Cvoid}, (Ptr{UInt8}, Cint), der, length(der))
    pkey = GC.@preserve der ccall((:d2i_PKCS8PrivateKey_bio, libcrypto), Ptr{Cvoid},
      (Ptr{Cvoid}, Ptr{Ptr{Cvoid}}, Ptr{Cvoid}, Cstring), bio, C_NULL, C_NULL, password)
    ccall((:BIO_free, libcrypto), Cint, (Ptr{Cvoid},), bio)
    pkey
  end
  pkey = attempt()
  if pkey == C_NULL  # pre-2020 keystores use legacy PBE ciphers (3DES/RC2)
    try load_legacy_provider() catch end  # provider module may not ship with this OpenSSL build
    pkey = attempt()
  end
  pkey == C_NULL && error("could not decrypt private key: wrong password or unsupported cipher")
  EvpPKey(pkey)
end

"""
Load a machine credential from an ABR `keystore.xml`. Picks the first
`<credential>` unless `id` or `abn` selects one (the ATO's EVTE keystore
holds one credential per test-entity ABN). The leaf certificate is matched
to the credential's `<serialNumber>`.
"""
load(path::AbstractString, password::AbstractString; id=nothing, abn=nothing) = begin
  doc = parsexml(read(path, String))
  sel = id !== nothing ? """//c:credential[@id="$id"]""" :
        abn !== nothing ? """//c:credential[c:abn="$abn"]""" : "//c:credential[1]"
  cred = findfirst(sel, root(doc), CNS)
  cred === nothing && error("credential $(something(id, abn, 1)) not found in $path")
  field(name) = (n = findfirst("./c:$name", cred, CNS); n === nothing ? "" : n.content)
  serial = field("serialNumber")
  certs = cms_certs(b64(field("publicCertificate")))
  leaf = Base.findfirst(c -> c.serial == serial, certs)
  leaf === nothing && (leaf = 1)  # fall back to first cert
  Credential(
    cred["id"], field("abn"), field("legalName"), serial, field("notAfter"),
    certs[leaf].der, [c.der for c in certs],
    decrypt_pkcs8(b64(field("protectedPrivateKey")), password))
end
