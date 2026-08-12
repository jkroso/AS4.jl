# Pure scoring helpers — no network, no suite required for the unit cases.
# When AS4_SUITE points at a full suite with results/, also re-scores them.
@use "./suite_fixtures.jl" error_codes business_codes code_counts score_response expected_response_path score_response_files
@use Test...

@testset "error_codes extracts values" begin
  xml = """<Event><Error.Code>CMN.ATO.GEN.OK</Error.Code>
           <Error.Code>SBR.GEN.INFO.1</Error.Code>
           <tns:Error.Code>CMN.ATO.PAYEVNT.000193</tns:Error.Code></Event>"""
  @test error_codes(xml) == ["CMN.ATO.GEN.OK", "SBR.GEN.INFO.1", "CMN.ATO.PAYEVNT.000193"]
  @test business_codes(xml) == ["CMN.ATO.GEN.OK", "CMN.ATO.PAYEVNT.000193"]
  @test code_counts(business_codes(xml)) == Dict("CMN.ATO.GEN.OK" => 1, "CMN.ATO.PAYEVNT.000193" => 1)
end

@testset "score_response matches on business multiset only" begin
  expected = """
    <Error.Code>SBR.GEN.INFO.1</Error.Code>
    <Error.Code>CMN.ATO.GEN.OK</Error.Code>
    <Error.Code>SBR.GEN.INFO.2</Error.Code>"""
  # Minified EVTE shape: same business code, different transport-info counts.
  actual = "<Error.Code>SBR.GEN.INFO.1</Error.Code><Error.Code>CMN.ATO.GEN.OK</Error.Code>" *
           "<Error.Code>SBR.GEN.INFO.2</Error.Code><Error.Code>SBR.GEN.INFO.4</Error.Code>"
  ok, exp, act = score_response(actual, expected)
  @test ok
  @test exp == Dict("CMN.ATO.GEN.OK" => 1)
  @test act == Dict("CMN.ATO.GEN.OK" => 1)

  wrong = "<Error.Code>CMN.ATO.PAYEVNT.000193</Error.Code>"
  ok2, _, act2 = score_response(wrong, expected)
  @test !ok2
  @test act2 == Dict("CMN.ATO.PAYEVNT.000193" => 1)
end

@testset "FAULT codes count as business" begin
  xml = "<Error.Code>SBR.GEN.FAULT.SERVICEACTIONDENIED</Error.Code>"
  @test business_codes(xml) == ["SBR.GEN.FAULT.SERVICEACTIONDENIED"]
end

@testset "expected_response_path maps Request → Response" begin
  dir = mktempdir()
  req = joinpath(dir, "CONF-ATO-PAYEVNT-BULK-001_Submit_Request_01.xml")
  resp = joinpath(dir, "CONF-ATO-PAYEVNT-BULK-001_Submit_Response_01.xml")
  write(req, "<x/>"); write(resp, "<Error.Code>CMN.ATO.GEN.OK</Error.Code>")
  @test expected_response_path(req) == resp
  @test expected_response_path(joinpath(dir, "missing_Request_01.xml")) === nothing
  ok, _, _ = score_response_files([resp], resp)
  @test ok
end

# Optional: re-score a real suite results/ tree when present (maintainer machine).
const suite = expanduser(get(ENV, "AS4_SUITE", "/path/to/payevnt-suite/inner"))
const results = joinpath(dirname(suite), "results")
if isdir(suite) && isdir(results)
  @testset "existing results score 21/21 against suite expected" begin
    npass = nfail = 0
    for dir in sort(readdir(results; join=true))
      isdir(dir) || continue
      base = basename(dir)
      m = match(r"^(BULK-\d+)_(Submit|Update|Adjust)_(\d+)$", base)
      m === nothing && continue
      scenario, action, n = m.captures
      req = joinpath(suite, "CONF-ATO-PAYEVNT-$scenario",
                     "CONF-ATO-PAYEVNT-$(scenario)_$(action)_Request_$(lpad(n, 2, '0')).xml")
      exp = expected_response_path(req)
      exp === nothing && continue
      actuals = sort(filter(p -> endswith(p, ".xml"), readdir(dir; join=true)))
      isempty(actuals) && continue
      ok, _, _ = score_response_files(actuals, exp)
      ok ? (npass += 1) : (nfail += 1)
      @test ok
    end
    @test npass == 21
    @test nfail == 0
  end
end
