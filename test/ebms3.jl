@use "../ebMS3.jl" UserMessage Part envelope secure! parse_response Receipt EbMSError TransportError isempty_mpc EB S12 WSU WSSE SAML2
@use "../XMLSig.jl" verify load_pem_keypair DS
@use "../MIME.jl" mime_encode MimePart
@use EzXML: parsexml, root
@use CodecZlib: GzipDecompressor
@use Test...

const pair = load_pem_keypair(joinpath(@__DIR__, "fixtures/key.pem"), joinpath(@__DIR__, "fixtures/cert.pem"))

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

# ── response parsing ──────────────────────────────────────────────────────────

const EBBP = "http://docs.oasis-open.org/ebxml-bp/ebbp-signals-2.0"
const DSNS = "http://www.w3.org/2000/09/xmldsig#"
soapenv(header) = """<S12:Envelope xmlns:S12="$S12"><S12:Header><eb:Messaging xmlns:eb="$EB">$header</eb:Messaging></S12:Header><S12:Body/></S12:Envelope>"""
signal(info, body) = soapenv("""<eb:SignalMessage><eb:MessageInfo>$info</eb:MessageInfo>$body</eb:SignalMessage>""")

@testset "parse Receipt with NRI digests" begin
  raw = signal(
    "<eb:Timestamp>2026-06-11T00:00:00.000Z</eb:Timestamp><eb:MessageId>r1@ato</eb:MessageId><eb:RefToMessageId>m1@centient</eb:RefToMessageId>",
    """<eb:Receipt><ebbp:NonRepudiationInformation xmlns:ebbp="$EBBP"><ebbp:MessagePartNRInformation><ds:Reference xmlns:ds="$DSNS" URI="#soapbody"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>q83vEjRWeJA=</ds:DigestValue></ds:Reference></ebbp:MessagePartNRInformation></ebbp:NonRepudiationInformation></eb:Receipt>""")
  r = parse_response(Vector{UInt8}(raw), "application/soap+xml")
  @test r isa Receipt
  @test r.ref_to_message_id == "m1@centient"
  @test r.digests == ["#soapbody" => "q83vEjRWeJA="]
end

@testset "parse ebMS Error / empty MPC" begin
  raw = signal(
    "<eb:Timestamp>2026-06-11T00:00:00.000Z</eb:Timestamp><eb:MessageId>e1@ato</eb:MessageId><eb:RefToMessageId>m2@centient</eb:RefToMessageId>",
    """<eb:Error errorCode="EBMS:0006" severity="failure" shortDescription="EmptyMessagePartitionChannel" category="Communication"><eb:ErrorDetail>nothing queued</eb:ErrorDetail></eb:Error>""")
  e = parse_response(Vector{UInt8}(raw), "application/soap+xml")
  @test e isa EbMSError
  @test e.code == "EBMS:0006" && e.severity == "failure"
  @test isempty_mpc(e)
  @test e.ref_to_message_id == "m2@centient"
end

@testset "parse phase4 UserMessage12 fixture" begin
  raw = read(joinpath(@__DIR__, "fixtures/phase4/UserMessage12.xml"))
  m = parse_response(raw, "application/soap+xml")
  @test m isa UserMessage
  @test m.action != "" && m.service != ""
  @test m.message_id != "" && m.from[1] != ""
end

@testset "pulled multipart message round-trips with gzip" begin
  msg = mkmsg()
  doc, atts = envelope(msg)
  parts = [MimePart("application/soap+xml; charset=UTF-8", Vector{UInt8}(string(doc)); id="root@as4");
           [MimePart("application/gzip", bytes; id=cid) for (cid, bytes) in atts]]
  body, ctype = mime_encode(parts)
  m = parse_response(body, ctype)
  @test m isa UserMessage
  @test m.message_id == msg.message_id
  @test length(m.parts) == 1 && m.parts[1].bytes == payload
end

@testset "SOAP fault without eb:Messaging is a TransportError" begin
  raw = """<S12:Envelope xmlns:S12="$S12"><S12:Body><S12:Fault><S12:Code><S12:Value>S12:Sender</S12:Value></S12:Code><S12:Reason><S12:Text xml:lang="en">bad request</S12:Text></S12:Reason></S12:Fault></S12:Body></S12:Envelope>"""
  @test_throws TransportError parse_response(Vector{UInt8}(raw), "application/soap+xml")
end

# ── WS-Security header (SBR profile shape) ────────────────────────────────────

fake_assertion() = root(parsexml("""<saml2:EncryptedAssertion xmlns:saml2="$SAML2"><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">opaque-ciphertext</xenc:EncryptedData></saml2:EncryptedAssertion>"""))

@testset "secured envelope: BST + assertion + 4-part signature" begin
  msg = mkmsg()
  doc, atts = envelope(msg)
  secure!(doc, atts, pair, fake_assertion())
  wns = [ns; "wsse"=>WSSE; "ds"=>DS; "saml2"=>SAML2]
  sec = findfirst("//wsse:Security", root(doc), wns)
  @test sec !== nothing
  @test findfirst(".//wsse:BinarySecurityToken", sec, wns) !== nothing
  @test findfirst(".//saml2:EncryptedAssertion", sec, wns) !== nothing
  @test findfirst(".//saml2:EncryptedAssertion//*[local-name()='EncryptedData']", sec, wns).content == "opaque-ciphertext"
  refs = [r["URI"] for r in findall(".//ds:Reference", sec, wns)]
  @test "#ebmessaging" in refs && "#soapbody" in refs && "#assertion" in refs
  @test any(startswith.(refs, "cid:"))
  # KeyInfo is a SecurityTokenReference to the BST, not X509Data
  @test findfirst(".//ds:KeyInfo/wsse:SecurityTokenReference/wsse:Reference", sec, wns)["URI"] == "#signingCert"
  @test verify(doc; cert=pair.cert_der, attachments=Dict(atts))
end

@testset "secured envelope without token (pre-STS use)" begin
  msg = mkmsg()
  doc, atts = envelope(msg)
  secure!(doc, atts, pair, nothing)
  refs = [r["URI"] for r in findall("//ds:Reference", root(doc), ["ds"=>DS])]
  @test !("#assertion" in refs) && "#ebmessaging" in refs
  @test verify(doc; cert=pair.cert_der, attachments=Dict(atts))
end

@testset "xmlsec1 oracle on the secured envelope" begin
  xmlsec1 = Sys.which("xmlsec1")
  if xmlsec1 === nothing
    @test_skip "xmlsec1 not installed"
  else
    msg = UserMessage(from=("1","t","r"), to=("2","t","r"), service="s", action="a")  # no attachments: xmlsec1 can't resolve cid:
    doc, atts = envelope(msg)
    secure!(doc, atts, pair, fake_assertion())
    path = tempname() * ".xml"
    write(path, string(doc))
    buf = IOBuffer()
    run(pipeline(ignorestatus(`$xmlsec1 verify --insecure --lax-key-search --pubkey-cert-pem $(joinpath(@__DIR__, "fixtures/cert.pem"))
                               --id-attr:Id $EB:Messaging --id-attr:Id $S12:Body --id-attr:Id $SAML2:EncryptedAssertion $path`),
                 stdout=buf, stderr=buf))
    @test occursin("Verification status: OK", String(take!(buf)))
  end
end
