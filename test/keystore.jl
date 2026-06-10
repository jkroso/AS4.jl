@use "../Keystore.jl" load Credential
@use "../XMLSig.jl" rsa_sign rsa_verify
@use Test...

# real (expired) EVTE M2M credentials from github.com/ato-pub/usi.cl.java
const PASSWORD = "Password1!"
const PATH = joinpath(@__DIR__, "fixtures/keystore-usi.xml")

@testset "ABR keystore" begin
  cred = load(PATH, PASSWORD)
  @test cred.abn == "11000002568"
  @test cred.legal_name == "INGLETON153"
  @test length(cred.cert_der) > 500          # leaf cert, DER
  @test !isempty(cred.chain)
  # the decrypted key signs; the leaf cert verifies it — keystore ↔ dsig integration
  sig = rsa_sign(cred.key, Vector{UInt8}("probe"))
  @test rsa_verify(cred.cert_der, Vector{UInt8}("probe"), sig)
  # second credential selectable by id
  cred2 = load(PATH, PASSWORD; id="ABRD:27809366375_USIMachine")
  @test cred2.abn == "27809366375" && cred2.cert_der != cred.cert_der
end

@testset "wrong password is a clear error" begin
  @test_throws ErrorException load(PATH, "wrong")
end
