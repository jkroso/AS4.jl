@use "../ebMS3.jl" UserMessage Part envelope push pull sync_call Receipt EbMSError TransportError S12 EB WSU
@use "../XMLSig.jl" load_pem_keypair
@use Sockets: listen, accept, getsockname, IPv4
@use Test...

const pair = load_pem_keypair(joinpath(@__DIR__, "fixtures/key.pem"), joinpath(@__DIR__, "fixtures/cert.pem"))

"Minimal one-request-per-connection HTTP server. handler(body)::Union{Tuple,Nothing} — nothing = drop the connection."
serve(handler) = begin
  server = listen(IPv4("127.0.0.1"), 0)
  port = getsockname(server)[2]
  @async while isopen(server)
    sock = try accept(server) catch; break end
    @async try
      buf = UInt8[]
      headend = 0
      while headend == 0
        append!(buf, readavailable(sock))
        r = findfirst(Vector{UInt8}("\r\n\r\n"), buf)
        r === nothing || (headend = last(r))
      end
      head = String(buf[1:headend])
      len = parse(Int, match(r"(?i)content-length:\s*(\d+)", head)[1])
      body = buf[headend+1:end]
      while length(body) < len
        append!(body, readavailable(sock))
      end
      resp = handler(body)
      if resp === nothing
        close(sock)
      else
        status, ctype, rbody = resp
        write(sock, "HTTP/1.1 $status OK\r\nContent-Type: $ctype\r\nContent-Length: $(length(rbody))\r\nConnection: close\r\n\r\n")
        write(sock, rbody)
        close(sock)
      end
    catch
      isopen(sock) && close(sock)
    end
  end
  server, "http://127.0.0.1:$port/as4"
end

reqid(body) = match(r"<eb:MessageId>([^<]+)</eb:MessageId>", String(copy(body)))[1]

receipt_for(id) = """<S12:Envelope xmlns:S12="$S12"><S12:Header><eb:Messaging xmlns:eb="$EB"><eb:SignalMessage><eb:MessageInfo><eb:Timestamp>2026-06-11T00:00:00.000Z</eb:Timestamp><eb:MessageId>r-$id</eb:MessageId><eb:RefToMessageId>$id</eb:RefToMessageId></eb:MessageInfo><eb:Receipt><ok/></eb:Receipt></eb:SignalMessage></eb:Messaging></S12:Header><S12:Body/></S12:Envelope>"""

empty_mpc() = """<S12:Envelope xmlns:S12="$S12"><S12:Header><eb:Messaging xmlns:eb="$EB"><eb:SignalMessage><eb:MessageInfo><eb:Timestamp>2026-06-11T00:00:00.000Z</eb:Timestamp><eb:MessageId>e1</eb:MessageId></eb:MessageInfo><eb:Error errorCode="EBMS:0006" severity="failure" shortDescription="EmptyMessagePartitionChannel"/></eb:SignalMessage></eb:Messaging></S12:Header><S12:Body/></S12:Envelope>"""

mkmsg() = UserMessage(
  from=("12345678901", "http://abr.gov.au/PartyIdType/ABN", "http://sbr.gov.au/ato/Role/Business"),
  to=("51824753556", "http://abr.gov.au/PartyIdType/ABN", "http://sbr.gov.au/agency"),
  service="http://sbr.gov.au/ato/payevnt/2020", action="Submit.004.00",
  parts=[Part(Vector{UInt8}("<PAYEVNT/>"); name="PAYEVNT", doctype="BASE")])

@testset "push → receipt" begin
  server, url = serve(body -> (200, "application/soap+xml", receipt_for(reqid(body))))
  msg = mkmsg()
  r = push(url, msg; cred=pair)
  @test r isa Receipt
  @test r.ref_to_message_id == msg.message_id
  close(server)
end

@testset "pull on empty channel → nothing" begin
  server, url = serve(body -> (200, "application/soap+xml", empty_mpc()))
  @test pull(url, "whatever@example"; cred=pair) === nothing
  close(server)
end

@testset "transport retry reuses the MessageId" begin
  seen = String[]
  first = Ref(true)
  server, url = serve(body -> begin
    Base.push!(seen, reqid(body))
    first[] ? (first[] = false; nothing) : (200, "application/soap+xml", receipt_for(reqid(body)))
  end)
  r = push(url, mkmsg(); cred=pair)
  @test r isa Receipt
  @test length(seen) == 2 && seen[1] == seen[2]   # same MessageId both attempts
  close(server)
end

@testset "retries exhausted → TransportError" begin
  server, url = serve(body -> nothing)
  @test_throws TransportError push(url, mkmsg(); cred=pair, retries=1)
  close(server)
end