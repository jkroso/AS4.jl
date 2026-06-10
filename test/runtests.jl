# Each file runs in its own process (they define overlapping test helpers).
const files = ["xmlsig.jl", "keystore.jl", "mime.jl", "ebms3.jl", "interop.jl", "meps.jl", "wstrust.jl", "sbr.jl"]
failed = String[]
for f in files
  println("\n━━ $f")
  ok = success(run(ignorestatus(`$(Base.julia_cmd()) --project=$(dirname(@__DIR__)) $(joinpath(@__DIR__, f))`)))
  ok || push!(failed, f)
end
isempty(failed) ? println("\nAll suites passed.") : error("failed: $(join(failed, ", "))")
