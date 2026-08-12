@use "../MIME.jl" MimePart mime_encode mime_parse parse_dump
@use Test...

fixture(name) = read(joinpath(@__DIR__, "fixtures/phase4", name))

@testset "multipart/related roundtrip" begin
  soap = MimePart("application/soap+xml; charset=UTF-8", Vector{UInt8}("<env/>"); id="root@as4")
  att = MimePart("application/gzip", UInt8[0x1f, 0x8b, 0x00, 0x01]; id="p1@as4",
                 headers=["Content-Transfer-Encoding" => "binary"])
  body, ctype = mime_encode([soap, att])
  @test occursin("multipart/related", ctype) && occursin("boundary=", ctype)
  parts = mime_parse(body, ctype)
  @test length(parts) == 2
  @test parts[1].id == "root@as4" && parts[1].bytes == soap.bytes
  @test parts[2].id == "p1@as4" && parts[2].bytes == att.bytes
  @test startswith(parts[2].mime, "application/gzip")
end

@testset "payload bytes survive a round trip exactly" begin
  # Only the single CRLF that delimits the boundary comes off. Stripping every
  # trailing CR/LF truncates any payload ending in a newline — including binary
  # attachments whose last bytes happen to be 0x0D/0x0A.
  for payload in [Vector{UInt8}("hello\n\n"), UInt8[0x1f, 0x8b, 0x08, 0x00, 0x0d, 0x0a],
                  Vector{UInt8}("x\r\n"), UInt8[0x0a], UInt8[0x0d], UInt8[], Vector{UInt8}("plain")]
    body, ctype = mime_encode([MimePart("application/soap+xml", Vector{UInt8}("<a/>"); id="root"),
                               MimePart("application/gzip", payload; id="p1")])
    @test mime_parse(body, ctype)[2].bytes == payload
  end
end

@testset "parse a real phase4 outbound capture (CRLF)" begin
  parts = parse_dump(fixture("dump-raw.as4out"))
  @test length(parts) >= 2
  @test occursin("Envelope", String(copy(parts[1].bytes)))
  @test occursin("soap+xml", parts[1].mime)
end

@testset "parse a real HTTP response capture (LF)" begin
  parts = parse_dump(fixture("helger.as4in"))
  @test length(parts) == 1   # bare soap+xml response, no multipart
  @test occursin("Envelope", String(copy(parts[1].bytes)))
end
