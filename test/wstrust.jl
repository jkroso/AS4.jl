@use "../WSTrust.jl" rst parse_rstr issue_token Token STSFault WST WSA
@use "../XMLSig.jl" verify load_pem_keypair S12 WSU WSSE DS SAML2
@use "../Keystore.jl" load
@use EzXML: parsexml, root
@use Dates: DateTime
@use Test...

const pair = load_pem_keypair(joinpath(@__DIR__, "fixtures/key.pem"), joinpath(@__DIR__, "fixtures/cert.pem"))
const ns = ["s"=>S12, "wsa"=>WSA, "wst"=>WST, "wsse"=>WSSE, "wsu"=>WSU, "ds"=>DS,
            "i"=>"http://schemas.xmlsoap.org/ws/2005/05/identity", "saml2"=>SAML2]

@testset "RST structure" begin
  doc = rst(pair, "https://softwareauthorisations.evte.ato.gov.au/R3.0/S007v1.3/service.svc", "https://test.sbr.gov.au/services")
  r = root(doc)
  @test findfirst("//wsa:Action", r, ns).content == "$WST/RST/Issue"
  @test findfirst("//wsa:To", r, ns).content == "https://softwareauthorisations.evte.ato.gov.au/R3.0/S007v1.3/service.svc"
  @test findfirst("//wst:RequestSecurityToken/wst:RequestType", r, ns).content == "$WST/Issue"
  @test findfirst("//wst:TokenType", r, ns).content == "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0"
  @test findfirst("//wst:KeyType", r, ns).content == "$WST/SymmetricKey"
  @test findfirst("//wst:KeySize", r, ns).content == "512"
  @test findfirst("//*[local-name()='AppliesTo']//wsa:Address", r, ns).content == "https://test.sbr.gov.au/services"
  @test length(findall("//i:ClaimType", r, ns)) == 16
  @test count(c -> c["Optional"] == "false", findall("//i:ClaimType", r, ns)) == 5
  # timestamp + addressed-to are signed with the credential key
  refs = [x["URI"] for x in findall("//ds:Reference", r, ns)]
  @test "#timestamp" in refs && "#msgto" in refs
  @test verify(doc; cert=pair.cert_der)
end

@testset "parse RSTR" begin
  raw = """<s:Envelope xmlns:s="$S12"><s:Header/><s:Body>
    <trust:RequestSecurityTokenResponseCollection xmlns:trust="$WST"><trust:RequestSecurityTokenResponse>
    <trust:KeySize>512</trust:KeySize>
    <trust:Lifetime><wsu:Created xmlns:wsu="$WSU">2026-06-11T00:00:00.000Z</wsu:Created><wsu:Expires xmlns:wsu="$WSU">2026-06-11T00:30:00.000Z</wsu:Expires></trust:Lifetime>
    <trust:RequestedSecurityToken><EncryptedAssertion xmlns="$SAML2"><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">blob</xenc:EncryptedData></EncryptedAssertion></trust:RequestedSecurityToken>
    <trust:RequestedProofToken><trust:BinarySecret>3q2+7w==</trust:BinarySecret></trust:RequestedProofToken>
    </trust:RequestSecurityTokenResponse></trust:RequestSecurityTokenResponseCollection></s:Body></s:Envelope>"""
  t = parse_rstr(Vector{UInt8}(raw))
  @test t isa Token
  @test t.proof_key == UInt8[0xde, 0xad, 0xbe, 0xef]
  @test t.expires == DateTime(2026, 6, 11, 0, 30)
  @test occursin("EncryptedAssertion", string(t.assertion))
end

@testset "STS fault → STSFault" begin
  raw = """<s:Envelope xmlns:s="$S12"><s:Body><s:Fault><s:Code><s:Value>s:Sender</s:Value></s:Code><s:Reason><s:Text xml:lang="en">Authentication failed: credential expired</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>"""
  @test_throws STSFault parse_rstr(Vector{UInt8}(raw))
  try parse_rstr(Vector{UInt8}(raw)) catch e
    @test occursin("credential expired", e.reason)
  end
end

if get(ENV, "AS4_LIVE", "") == "1"
  @testset "LIVE: EVTE STS smoke (public USI test keystore)" begin
    cred = load(joinpath(@__DIR__, "fixtures/keystore-usi.xml"), "Password1!")
    try
      t = issue_token(cred, "https://softwareauthorisations.evte.ato.gov.au/R3.0/S007v1.3/service.svc", "https://test.sbr.gov.au/services")
      @info "EVTE STS issued a token" expires = t.expires
      @test t isa Token
    catch e
      # an STSFault still proves transport + envelope shape reached the STS proper
      @info "EVTE STS replied with a fault (credential is expired 2024, so expected)" e
      @test e isa STSFault
    end
  end
end