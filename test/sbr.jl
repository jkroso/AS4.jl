@use "../SBR.jl" Env endpoints sts payevnt_message as_message business_party agent_party ATO_ABN
@use Test...

@testset "endpoints" begin
  evte = endpoints(Env.EVTE)
  @test evte.bulk_push == "https://test2.ato.sbr.gov.au/services/BulkBatch-async-push"
  @test evte.bulk_pull == "https://test2.ato.sbr.gov.au/services/BulkBatch-async-pull"
  @test evte.single_sync == "https://test2.ato.sbr.gov.au/services/Single-sync"
  @test endpoints(Env.PROD).single_async == "https://prod2.ato.sbr.gov.au/services/Single-async-push-pull"
  @test sts(Env.EVTE).url == "https://softwareauthorisations.evte.ato.gov.au/R3.0/S007v1.3/service.svc"
  @test sts(Env.EVTE).applies_to == "https://test.sbr.gov.au/services"
  @test sts(Env.PROD).url == "https://softwareauthorisations.ato.gov.au/R3.0/S007v1.3/service.svc"
  @test sts(Env.PROD).applies_to == "https://sbr.gov.au/services"
end

@testset "parties" begin
  @test business_party("12 345 678 901") == ("12345678901", "http://abr.gov.au/PartyIdType/ABN", "http://sbr.gov.au/ato/Role/Business")
  @test agent_party("24690666") == ("24690666", "http://ato.gov.au/PartyIdType/TAN", "http://sbr.gov.au/ato/Role/Registered Agent")
end

@testset "payevnt message shape" begin
  msg = payevnt_message(Vector{UInt8}("<PAYEVNT/>");
    abn="12345678901", product_id="ABC123", bms=("Centient", "Centient", "1.0"))
  @test msg.service == "http://sbr.gov.au/ato/payevnt/2020"
  @test msg.action == "Submit.004.00"
  @test msg.to == (ATO_ABN, "http://abr.gov.au/PartyIdType/ABN", "http://sbr.gov.au/agency")
  @test msg.from[1] == "12345678901" && msg.from[3] == "http://sbr.gov.au/ato/Role/Business"
  props = Dict(msg.properties)
  @test props["ProductID"] == "ABC123" && props["BMS Vendor"] == "Centient" && props["BMS Version"] == "1.0"
  @test length(msg.parts) == 1 && msg.parts[1].name == "PAYEVNT" && msg.parts[1].doctype == "BASE"
end

@testset "AS message shape" begin
  msg = as_message(:submit, Vector{UInt8}("<AS/>"); abn="12345678901", product_id="X", bms=("C","C","1"))
  @test msg.action != "" && occursin("/ato/as/", msg.service)
  @test msg.parts[1].name == "AS"
  @test_throws ErrorException as_message(:frobnicate, UInt8[]; abn="1", product_id="X", bms=("C","C","1"))
end