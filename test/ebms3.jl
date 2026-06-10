@use "../ebMS3.jl" UserMessage Part envelope EB S12 WSU
@use EzXML: parsexml, root
@use CodecZlib: GzipDecompressor
@use Test...

const payload = Vector{UInt8}("<PAYEVNT><Rp><Abn>12345678901</Abn></Rp></PAYEVNT>")

mkmsg() = UserMessage(
  from=("12345678901", "http://abr.gov.au/PartyIdType/ABN", "http://sbr.gov.au/ato/Role/Business"),
  to=("51824753556", "http://abr.gov.au/PartyIdType/ABN", "http://sbr.gov.au/agency"),
  service="http://sbr.gov.au/ato/payevnt/2020", action="Submit.004.00",
  properties=["ProductID"=>"ABC123", "BMS Vendor"=>"Centient", "BMS Name"=>"Centient", "BMS Version"=>"1.0"],
  parts=[Part(payload; name="PAYEVNT", doctype="BASE", mime="text/xml")])

const ns = ["s"=>S12, "eb"=>EB, "wsu"=>WSU]

@testset "UserMessage envelope" begin
  msg = mkmsg()
  doc, atts = envelope(msg)
  r = root(doc)
  @test findfirst("//eb:UserMessage/eb:CollaborationInfo/eb:Action", r, ns).content == "Submit.004.00"
  @test findfirst("//eb:CollaborationInfo/eb:Service", r, ns).content == "http://sbr.gov.au/ato/payevnt/2020"
  @test findfirst("//eb:PartyInfo/eb:From/eb:PartyId", r, ns)["type"] == "http://abr.gov.au/PartyIdType/ABN"
  @test findfirst("//eb:PartyInfo/eb:To/eb:PartyId", r, ns).content == "51824753556"
  @test length(findall("//eb:MessageProperties/eb:Property", r, ns)) == 4
  @test findfirst("//eb:MessageInfo/eb:MessageId", r, ns).content == msg.message_id
  @test findfirst("//eb:AgreementRef", r, ns) === nothing   # omitted when not set
  # payload part: cid reference, gzip, part properties
  pi = findfirst("//eb:PayloadInfo/eb:PartInfo", r, ns)
  @test startswith(pi["href"], "cid:")
  props = Dict(p["name"] => p.content for p in findall(".//eb:PartProperties/eb:Property", pi, ns))
  @test props["CompressionType"] == "application/gzip"
  @test props["DocumentName"] == "PAYEVNT" && props["DocumentType"] == "BASE"
  @test props["MimeType"] == "text/xml"
  cid = pi["href"][5:end]
  @test length(atts) == 1 && atts[1].first == cid
  @test transcode(GzipDecompressor, atts[1].second) == payload
  # signable anchors
  @test findfirst("//eb:Messaging", r, ns)["wsu:Id"] == "ebmessaging"
  @test findfirst("//s:Body", r, ns)["wsu:Id"] == "soapbody"
  @test findfirst("//eb:Messaging", r, ns)["s:mustUnderstand"] == "true"
end

@testset "agreement ref when set" begin
  msg = UserMessage(from=("1","t","r"), to=("2","t","r"), service="s", action="a",
                    agreement="http://sbr.gov.au/agreement/Gateway/1.0/Push/PKI")
  doc, _ = envelope(msg)
  @test findfirst("//eb:AgreementRef", root(doc), ns).content == "http://sbr.gov.au/agreement/Gateway/1.0/Push/PKI"
end

@testset "xml escaping in properties" begin
  msg = UserMessage(from=("1","t","r"), to=("2","t","r"), service="s", action="a",
                    properties=["BMS Name"=>"Tools & Trade <Pty>"])
  doc, _ = envelope(msg)
  @test findfirst("//eb:Property", root(doc), ns).content == "Tools & Trade <Pty>"
end
