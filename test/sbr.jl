@use "../SBR.jl" Env endpoints sts payevnt_message as_message service_message bulk_payload business_party agent_party token_cache mep_for lodge_url ATO_ABN
@use "../Keystore.jl" load
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

@testset "one token cache per credential per environment" begin
  # `cache=TokenCache()` as a default argument is a fresh cache every call, so
  # every lodge and every collect_response poll would mint its own assertion.
  cred = load(joinpath(@__DIR__, "fixtures/keystore-usi.xml"), "Password1!")
  @test token_cache(Env.EVTE, cred) === token_cache(Env.EVTE, cred)
  @test token_cache(Env.EVTE, cred) !== token_cache(Env.PROD, cred)
  other = load(joinpath(@__DIR__, "fixtures/keystore-usi.xml"), "Password1!"; id="ABRD:27809366375_USIMachine")
  @test token_cache(Env.EVTE, cred) !== token_cache(Env.EVTE, other)
end

@testset "lodge URL follows SERVICES mep, not service-URI substrings" begin
  # payevntrecon's service URI *contains* "payevnt" — the old occursin check
  # would have sent recon to bulk_push. Route by the registry mep instead.
  pay, _ = payevnt_message(UInt8[], []; abn="1", product_id="X", bms=("C","C","1"))
  as = as_message(:submit, UInt8[]; abn="1", product_id="X", bms=("C","C","1"))
  recon = service_message(:payevntrecon_list, UInt8[]; abn="1", product_id="X", bms=("C","C","1"))
  @test mep_for(pay.service) == :bulk
  @test mep_for(as.service) == :sync
  @test mep_for(recon.service) == :sync
  @test mep_for("http://sbr.gov.au/ato/unknown/2099") == :sync
  @test lodge_url(Env.EVTE, pay) == endpoints(Env.EVTE).bulk_push
  @test lodge_url(Env.EVTE, as) == endpoints(Env.EVTE).single_sync
  @test lodge_url(Env.EVTE, recon) == endpoints(Env.EVTE).single_sync
  @test lodge_url(Env.PROD, pay) == endpoints(Env.PROD).bulk_push
end

@testset "AS message shape" begin
  msg = as_message(:submit, Vector{UInt8}("<AS/>"); abn="12345678901", product_id="X", bms=("C","C","1"))
  @test msg.action != "" && occursin("/ato/as/", msg.service)
  @test msg.parts[1].name == "AS"
  @test_throws ErrorException as_message(:frobnicate, UInt8[]; abn="1", product_id="X", bms=("C","C","1"))
end