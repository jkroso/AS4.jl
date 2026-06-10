@use "../XMLSig.jl" c14n verify
@use "../MIME.jl" parse_dump
@use EzXML: parsexml, root
@use SHA: sha1
@use Base64: base64encode
@use Test...

fixture(name) = parsexml(read(joinpath(@__DIR__, "fixtures/w3c", name), String))
b64(s) = replace(s, r"\s" => "")

@testset "W3C: enveloping rsa-sha256 (aleksey-xmldsig-01)" begin
  doc = fixture("enveloping-sha256-rsa-sha256.xml")
  @test verify(doc)
  findfirst("//*[@Id='object']", root(doc)).content = "tampered"
  @test !verify(doc)
end

@testset "W3C: exclusive c14n digests w/ PrefixList (merlin-exc-c14n-one)" begin
  doc = fixture("exc-signature.xml")
  ns = ["ds" => "http://www.w3.org/2000/09/xmldsig#"]
  refs = findall("//ds:Reference", root(doc), ns)
  @test length(refs) == 4
  digests = [b64(findfirst(".//ds:DigestValue", r, ns).content) for r in refs]
  obj = """//*[@Id="to-be-signed"]"""
  d(; kw...) = base64encode(sha1(Vector{UInt8}(c14n(doc, obj; kw...))))
  pl = ["bar", "#default"]
  @test d() == digests[1]                                       # plain exclusive
  @test d(inclusive_prefixes=pl) == digests[2]                  # + PrefixList
  @test d(comments=true) == digests[3]                          # WithComments
  @test d(comments=true, inclusive_prefixes=pl) == digests[4]   # WithComments + PrefixList
end

@testset "real AS4 captures from independent stacks verify" begin
  for name in ["helger.as4in", "governikus.as4in"]
    parts = parse_dump(read(joinpath(@__DIR__, "fixtures/phase4", name)))
    doc = parsexml(parts[1].bytes)
    @test verify(doc)  # cert taken from the embedded BinarySecurityToken
  end
end
