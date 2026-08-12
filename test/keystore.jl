@use "../Keystore.jl" load Credential expired expires_at
@use "../XMLSig.jl" rsa_sign rsa_verify
@use Dates: DateTime
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

@testset "credential expiry is knowable locally" begin
  # The STS answers an expired credential with E2169, which reads like a
  # protocol fault and isn't one. These fixtures expired in 2024.
  cred = load(PATH, PASSWORD)
  @test expires_at(cred) == DateTime(2024, 9, 11, 20, 10, 21)   # 06:10:21+10:00 → UTC
  @test expired(cred)
  @test !expired(cred, DateTime(2024, 1, 1))
  # absent or malformed notAfter is unknown, not expired
  blank = Credential("i", "a", "n", "s", "", UInt8[], Vector{UInt8}[], cred.key)
  @test expires_at(blank) === nothing
  @test !expired(blank)
end
