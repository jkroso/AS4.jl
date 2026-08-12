#=
Independent WSS4J oracle for a secured AS4 multipart message.

Requires a JVM and jbang (https://www.jbang.dev). Skips cleanly when either
is missing — this is cross-stack evidence, not a unit of the library.

  jbang test/oracle/Wss4jVerify.java /path/to/wire.mime

Or run this file; it builds a dump and invokes jbang when available:

  julia --project=. test/oracle_wss4j.jl
=#
@use "../ebMS3.jl" UserMessage Part envelope secure! wire
@use "../XMLSig.jl" load_pem_keypair
@use Test...

const pair = load_pem_keypair(joinpath(@__DIR__, "fixtures/key.pem"),
                              joinpath(@__DIR__, "fixtures/cert.pem"))
const jbang = Sys.which("jbang")
const oracle = joinpath(@__DIR__, "oracle", "Wss4jVerify.java")
const trust_pem = joinpath(@__DIR__, "fixtures", "cert.pem")

@testset "WSS4J oracle verifies a secured multipart dump" begin
  if jbang === nothing
    @info "skip WSS4J oracle — install jbang + a JDK, then re-run"
    @test true
  else
    msg = UserMessage(
      from=("12345678901", "http://abr.gov.au/PartyIdType/ABN", "http://sbr.gov.au/ato/Role/Business"),
      to=("51824753556", "http://abr.gov.au/PartyIdType/ABN", "http://sbr.gov.au/agency"),
      service="http://sbr.gov.au/ato/payevnt/2020", action="Submit.004.00",
      parts=[Part(Vector{UInt8}("<PAYEVNT/>"); name="PAYEVNT", doctype="BASE")])
    doc, atts = envelope(msg)
    secure!(doc, atts, pair, nothing)
    body, ctype = wire(doc, atts)
    path = joinpath(tempdir(), "as4-wss4j-$(getpid()).mime")
    open(path, "w") do io
      # Same shape the phase4 captures use: HTTP headers + body, so the Java
      # oracle can pull Content-Type and split the multipart.
      write(io, "Content-Type: $ctype\r\n\r\n")
      write(io, body)
    end
    try
      # Pass the fixture cert as Merlin trust material — self-signed BSTs fail
      # path validation against an empty trust store.
      proc = run(ignorestatus(`$jbang $oracle $path $trust_pem`))
      @test success(proc)
    finally
      isfile(path) && rm(path)
    end
  end
end
