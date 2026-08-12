@use "../SBR.jl" Env endpoints sts payevnt_message as_message service_message bulk_payload business_party agent_party ATO_ABN
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

@testset "bulk payload record delimiters" begin
  bytes, ids = bulk_payload("PAYEVNT" => "<P/>", ["PAYEVNTEMP" => "<C1/>", "PAYEVNTEMP" => "<C2/>"])
  s = String(bytes)
  # Parent first, children after, each document preceded by its delimiter.
  @test ids == ["1.1", "1.2", "1.3"]
  @test occursin("""<Record_Delimiter DocumentID="1.1" DocumentName="PAYEVNT" DocumentType="PARENT" RelatedDocumentID=""/>\n<P/>""", s)
  @test occursin("""<Record_Delimiter DocumentID="1.2" DocumentName="PAYEVNTEMP" DocumentType="CHILD" RelatedDocumentID="1.1"/>\n<C1/>""", s)
  @test occursin("""<Record_Delimiter DocumentID="1.3" DocumentName="PAYEVNTEMP" DocumentType="CHILD" RelatedDocumentID="1.1"/>\n<C2/>""", s)
  @test findfirst("<P/>", s) < findfirst("<C1/>", s) < findfirst("<C2/>", s)

  # Batch: each parent starts a new group, and its children point back at it.
  _, batch = bulk_payload([("PAYEVNT" => "<P1/>") => ["PAYEVNTEMP" => "<C/>"],
                           ("PAYEVNT" => "<P2/>") => ["PAYEVNTEMP" => "<C/>"]])
  @test batch == ["1.1", "1.2", "2.1", "2.2"]
end

@testset "payevnt message shape" begin
  msg, ids = payevnt_message(Vector{UInt8}("<PAYEVNT/>"), [Vector{UInt8}("<PAYEVNTEMP/>")];
    abn="12345678901", product_id="ABC123", bms=("Example Vendor", "Example Payroll", "1.0"))
  @test msg.service == "http://sbr.gov.au/ato/payevnt/2020"
  @test msg.action == "Submit.004.00"
  @test msg.to == (ATO_ABN, "http://abr.gov.au/PartyIdType/ABN", "http://sbr.gov.au/agency")
  @test msg.from[1] == "12345678901" && msg.from[3] == "http://sbr.gov.au/ato/Role/Business"
  props = Dict(msg.properties)
  @test props["ProductID"] == "ABC123"
  @test props["BMS Vendor"] == "Example Vendor"
  @test props["BMS Name"] == "Example Payroll"
  @test props["BMS Version"] == "1.0"
  # One attachment for the whole transmission — both documents live inside it.
  @test length(msg.parts) == 1 && msg.parts[1].name == "PAYEVNT"
  @test msg.parts[1].doctype == "BASE"  # EVTE rejects a bulk push without one
  @test ids == ["1.1", "1.2"]
  body = String(copy(msg.parts[1].bytes))
  @test occursin("<PAYEVNT/>", body) && occursin("<PAYEVNTEMP/>", body)
  @test count("<Record_Delimiter", body) == 2

  @test payevnt_message(UInt8[], []; kind=:update, abn="1", product_id="X", bms=("C","C","1"))[1].action == "Update.004.00"
  # The bulk services must not be reachable through the single-document path.
  @test_throws ErrorException service_message(:payevnt_submit, UInt8[]; abn="1", product_id="X", bms=("C","C","1"))
end

@testset "AS message shape" begin
  msg = as_message(:submit, Vector{UInt8}("<AS/>"); abn="12345678901", product_id="X", bms=("C","C","1"))
  @test msg.action != "" && occursin("/ato/as/", msg.service)
  @test msg.parts[1].name == "AS"
  @test_throws ErrorException as_message(:frobnicate, UInt8[]; abn="1", product_id="X", bms=("C","C","1"))
end