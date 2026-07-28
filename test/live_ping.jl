#=
MSH Ping — the WIG's "message connectivity test". A bare signed UserMessage
against the ebMS3 test service; isolates envelope + WS-Security correctness
from any business payload/service configuration.

  AS4_KEYSTORE=… AS4_PASSWORD=… julia --project=. test/live_ping.jl
=#
@use "../SBR.jl" Env sts endpoints business_party ato_party
@use "../ebMS3.jl" UserMessage Receipt EbMSError TransportError push
@use "../WSTrust.jl" issue_token
@use "../Keystore.jl" load

const ABN = "67094544519"  # YALACT129
cred = load(expanduser(ENV["AS4_KEYSTORE"]), ENV["AS4_PASSWORD"]; id="ABRD:$(ABN)_YALACT129")

msg = UserMessage(from=business_party(ABN), to=ato_party(),
  service="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/service",
  action="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/test")

s, eps = sts(Env.EVTE), endpoints(Env.EVTE)
token = issue_token(cred, s.url, s.applies_to)
@info "STS token issued" expires = token.expires

url = get(ENV, "AS4_PING_URL", eps.single_sync)
assertion = haskey(ENV, "AS4_NO_ASSERTION") ? nothing : token.assertion
@info "pinging" url msg.message_id assertion === nothing
r = try
  push(url, msg; cred=cred, assertion=assertion)
catch e
  @error "ping failed" exception = e
  exit(1)
end
@info "PONG" typeof(r) r
