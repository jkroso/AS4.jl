@use UUIDs: uuid4

const CRLF = "\r\n"

"One part of a multipart/related message. `id` is the Content-ID without angle brackets."
struct MimePart
  mime::String
  bytes::Vector{UInt8}
  id::String
  headers::Vector{Pair{String,String}}
end
MimePart(mime, bytes; id="", headers=Pair{String,String}[]) = MimePart(mime, Vector{UInt8}(bytes), id, headers)

"""
Encode parts as `multipart/related`. Returns `(body_bytes, content_type)`.
The first part is the root (`type`/`start` parameters point at it).
"""
mime_encode(parts::Vector{MimePart}) = begin
  boundary = "=_Part_$(uuid4())"
  io = IOBuffer()
  for p in parts
    write(io, "--", boundary, CRLF)
    write(io, "Content-Type: ", p.mime, CRLF)
    isempty(p.id) || write(io, "Content-ID: <", p.id, ">", CRLF)
    for (k, v) in p.headers
      write(io, k, ": ", v, CRLF)
    end
    write(io, CRLF)
    write(io, p.bytes)
    write(io, CRLF)
  end
  write(io, "--", boundary, "--", CRLF)
  roottype = split(parts[1].mime, ';')[1]
  ctype = """multipart/related; boundary="$boundary"; type="$roottype"; charset=UTF-8""" *
          (isempty(parts[1].id) ? "" : """; start="<$(parts[1].id)>" """ |> rstrip)
  take!(io), String(ctype)
end

"Case-insensitive header lookup in a raw header block."
header(block::AbstractString, name) = begin
  m = match(Regex("(?im)^$name:[ \\t]*(.*?)\\r?\$"), block)
  m === nothing ? "" : String(m[1])
end

findbytes(hay::Vector{UInt8}, needle::Vector{UInt8}, from=1) = begin
  r = Base.findnext(needle, hay, from)
  r === nothing ? 0 : first(r)
end

"Split raw bytes at the first blank line, returning (header_string, body_bytes)."
splitblock(bytes::Vector{UInt8}) = begin
  i = findbytes(bytes, Vector{UInt8}("\r\n\r\n"))
  n = 4
  if i == 0
    i = findbytes(bytes, Vector{UInt8}("\n\n"))
    n = 2
  end
  i == 0 ? (String(copy(bytes)), UInt8[]) : (String(bytes[1:i-1]), bytes[i+n:end])
end

"Parse a `multipart/related` body into MimeParts."
mime_parse(body::Vector{UInt8}, content_type::AbstractString) = begin
  m = match(r"boundary=\"?([^\";]+)\"?"i, content_type)
  m === nothing && error("no boundary in Content-Type: $content_type")
  sep = Vector{UInt8}("--" * m[1])
  parts = MimePart[]
  pos = findbytes(body, sep)
  while pos != 0
    from = pos + length(sep)
    # closing delimiter?
    from + 1 <= length(body) && body[from] == UInt8('-') && body[from+1] == UInt8('-') && break
    # skip the CRLF after the boundary line
    while from <= length(body) && (body[from] == UInt8('\r') || body[from] == UInt8('\n'))
      from += 1
      body[from-1] == UInt8('\n') && break
    end
    next = findbytes(body, sep, from)
    next == 0 && break
    chunk = body[from:next-1]
    # part body ends with CRLF before the next boundary
    headers, content = splitblock(chunk)
    while !isempty(content) && (content[end] == UInt8('\n') || content[end] == UInt8('\r'))
      pop!(content)
    end
    id = replace(header(headers, "Content-ID"), r"^<|>$" => "")
    push!(parts, MimePart(header(headers, "Content-Type"), content; id=id))
    pos = next
  end
  parts
end

"""
Parse a raw message dump — either an HTTP response or a bare MIME message with
prologue headers (phase4 `.as4in`/`.as4out` style). Returns the MimeParts; a
non-multipart body comes back as a single part.
"""
parse_dump(bytes::Vector{UInt8}) = begin
  headers, body = splitblock(bytes)
  startswith(headers, "HTTP/") && ((headers, body) = splitblock(body) |> x -> (headers * "\n" * x[1], x[2]))
  ctype = header(headers, "Content-Type")
  if occursin("multipart/related", ctype)
    mime_parse(body, ctype)
  elseif occursin("multipart/related", String(body[1:min(end, 2000)]))
    # some dumps repeat headers; find the Content-Type line inside the body prologue
    h2, b2 = splitblock(body)
    mime_parse(b2, header(h2, "Content-Type"))
  else
    [MimePart(ctype, body)]
  end
end
