@use "../XMLSig.jl" c14n sign! verify signed_uris rsa_verify xpath_literal count_id load_pem_keypair WSU DS S12
@use EzXML: parsexml, root
@use Base64: base64decode
@use Test...

const pair = load_pem_keypair(joinpath(@__DIR__, "fixtures/key.pem"), joinpath(@__DIR__, "fixtures/cert.pem"))

@testset "exclusive c14n" begin
  # unused namespaces dropped, comments stripped, attrs sorted, empty tags expanded
  doc = parsexml("""<a xmlns:u="urn:u"><b z="1" a="2" xmlns:v="urn:v">hi<!--c--></b><c/></a>""")
  @test c14n(doc) == """<a><b a="2" z="1">hi</b><c></c></a>"""
  # visibly-used namespace kept
  doc2 = parsexml("""<a xmlns:u="urn:u"><u:b/></a>""")
  @test c14n(doc2) == """<a><u:b xmlns:u="urn:u"></u:b></a>"""
  # subtree canonicalization in document context
  doc3 = parsexml("""<r xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:X/></ds:SignedInfo></r>""")
  @test c14n(doc3, "//ds:SignedInfo") == """<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X></ds:X></ds:SignedInfo>"""
  # subtree selection by wsu:Id predicate
  wsu = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
  doc4 = parsexml("""<r xmlns:wsu="$wsu"><x wsu:Id="a">1</x><x wsu:Id="b">2</x></r>""")
  @test c14n(doc4, """//*[@wsu:Id="b"]""") == """<x xmlns:wsu="$wsu" wsu:Id="b">2</x>"""
end

soapdoc() = parsexml("""<s:Envelope xmlns:s="$S12" xmlns:wsu="$WSU"><s:Header><x wsu:Id="hdr">meta</x><sec/></s:Header><s:Body wsu:Id="body">data</s:Body></s:Envelope>""")
secnode(doc) = findfirst("//sec", root(doc))

@testset "sign! + verify roundtrip" begin
  doc = soapdoc()
  sign!(doc, secnode(doc), ["hdr", "body"], pair)
  @test verify(doc; cert=pair.cert_der)
  # signature node landed under <sec/> with both references
  sig = findfirst("//ds:Signature", root(doc), ["ds"=>DS])
  @test sig !== nothing
  uris = [r["URI"] for r in findall(".//ds:Reference", sig, ["ds"=>DS])]
  @test sort(uris) == ["#body", "#hdr"]
  # tampering with any signed element breaks it
  findfirst("//s:Body", root(doc), ["s"=>S12]).content = "evil"
  @test !verify(doc; cert=pair.cert_der)
end

@testset "verify uses embedded KeyInfo cert when none given" begin
  doc = soapdoc()
  sign!(doc, secnode(doc), ["body"], pair)
  @test verify(doc)
end

@testset "SwA attachment refs" begin
  doc = soapdoc()
  att = Dict("part1@as4" => Vector{UInt8}("gzipped-bytes-pretend"))
  sign!(doc, secnode(doc), ["body"], pair; attachments=att)
  uris = [r["URI"] for r in findall("//ds:Reference", root(doc), ["ds"=>DS])]
  @test "cid:part1@as4" in uris
  @test verify(doc; cert=pair.cert_der, attachments=att)
  @test !verify(doc; cert=pair.cert_der, attachments=Dict("part1@as4" => UInt8['x']))
  @test !verify(doc; cert=pair.cert_der)  # attachment missing entirely
end

@testset "a Reference must resolve to exactly one element" begin
  # A missing Id used to digest the empty node set: a signature that verifies
  # and covers nothing.
  doc = soapdoc()
  @test_throws ErrorException sign!(doc, secnode(doc), ["body", "typo"], pair)
  # Two elements sharing an Id digest their concatenation, which is not what
  # "#dup" says.
  dup = parsexml("""<s:Envelope xmlns:s="$S12" xmlns:wsu="$WSU"><s:Header><sec/></s:Header><s:Body wsu:Id="dup"><x wsu:Id="dup"/></s:Body></s:Envelope>""")
  @test count_id(dup, "dup") == 2
  @test_throws ErrorException sign!(dup, findfirst("//sec", root(dup)), ["dup"], pair)
end

@testset "a signature covering nothing does not verify" begin
  doc = parsexml("""<r xmlns:ds="$DS"><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="$(("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"))"/></ds:SignedInfo><ds:SignatureValue>x</ds:SignatureValue></ds:Signature></r>""")
  @test verify(doc; cert=pair.cert_der) == false   # `all` over zero refs would say true
end

@testset "each signature signs its own SignedInfo" begin
  # `//ds:SignedInfo` picks the first in the document, so a second signature —
  # or a document that already carries an STS-signed assertion — would get a
  # SignatureValue over someone else's bytes.
  doc = parsexml("""<s:Envelope xmlns:s="$S12" xmlns:wsu="$WSU"><s:Header><a wsu:Id="hdr"/><sec/></s:Header><s:Body wsu:Id="body">data</s:Body></s:Envelope>""")
  sign!(doc, secnode(doc), ["hdr"], pair)
  sign!(doc, secnode(doc), ["body"], pair)
  sigs = findall("//ds:Signature", root(doc), ["ds"=>DS])
  @test length(sigs) == 2
  si(i) = Vector{UInt8}(c14n(findfirst("./ds:SignedInfo", sigs[i], ["ds"=>DS])))
  sv(i) = base64decode(findfirst("./ds:SignatureValue", sigs[i], ["ds"=>DS]).content)
  @test si(1) != si(2)
  @test rsa_verify(pair.cert_der, si(1), sv(1))
  @test rsa_verify(pair.cert_der, si(2), sv(2))
  @test !rsa_verify(pair.cert_der, si(1), sv(2))
end

@testset "a Reference URI cannot splice into the XPath" begin
  # URIs in a document we did not write are attacker-supplied.
  @test xpath_literal("plain") == "\"plain\""
  @test xpath_literal("it's") == "\"it's\""
  @test xpath_literal("say \"hi\"") == "concat(\"say \", '\"', \"hi\", '\"', \"\")"
  doc = soapdoc()
  sign!(doc, secnode(doc), ["body"], pair)
  findfirst("//ds:Reference", root(doc), ["ds"=>DS])["URI"] = """#body"] | //*[@wsu:Id=" """
  @test verify(doc; cert=pair.cert_der) == false
end

@testset "require= gates on what the signature actually covers" begin
  doc = soapdoc()
  sign!(doc, secnode(doc), ["body"], pair)
  @test signed_uris(doc) == ["#body"]
  @test verify(doc; cert=pair.cert_der, require=["body"])
  @test verify(doc; cert=pair.cert_der, require=["#body"])
  # the header is unsigned — a caller that reads it must not be told otherwise
  @test !verify(doc; cert=pair.cert_der, require=["body", "hdr"])
end

@testset "c14n does not leak libxml2 allocations" begin
  doc = parsexml("""<r xmlns:wsu="$WSU"><x wsu:Id="a">$(repeat("payload ", 200))</x></r>""")
  for _ in 1:2_000; c14n(doc, """//*[@wsu:Id="a"]"""); end   # warm up
  GC.gc(); before = Sys.maxrss()
  for _ in 1:20_000; c14n(doc, """//*[@wsu:Id="a"]"""); end
  GC.gc()
  # the canonicalized buffer, XPath context and XPath object all need freeing;
  # leaking them cost ~3.7 KB a call, unbounded in a long-lived process
  @test (Sys.maxrss() - before) / 2^20 < 5
end

@testset "xmlsec1 oracle" begin
  xmlsec1 = Sys.which("xmlsec1")
  if xmlsec1 === nothing
    @test_skip "xmlsec1 not installed"
  else
    doc = soapdoc()
    sign!(doc, secnode(doc), ["hdr", "body"], pair)
    path = tempname() * ".xml"
    write(path, string(doc))
    # xmlsec1 registers wsu:Id-style references per *node* type: --id-attr:Id <node-ns>:<name>
    buf = IOBuffer()
    run(pipeline(ignorestatus(`$xmlsec1 verify --insecure --id-attr:Id x --id-attr:Id $S12:Body $path`), stdout=buf, stderr=buf))
    @test occursin("Verification status: OK", String(take!(buf)))
  end
end
