@use "../XMLSig.jl" c14n sign! verify load_pem_keypair WSU DS S12
@use EzXML: parsexml, root
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
    out = read(pipeline(ignorestatus(`$xmlsec1 verify --insecure --id-attr:Id x --id-attr:Id $S12:Body $path`), stderr=stdout), String)
    @test occursin("Verification status: OK", out)
  end
end
