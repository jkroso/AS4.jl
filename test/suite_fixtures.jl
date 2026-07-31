#=
Reading the ATO conformance suite's payload files.

The suite ships mandatory fields *empty* so the payloads don't age — the DSP
injects its own current values (suite doc, "Removal of date values"). The
listed fields are all dates bar one: PAYEVNTEMP272 Lump Sum Financial Year is
an Int, so it needs its own substitution. Left blank, EVTE answers
CMN.ATO.GEN.XML03 — "The string '' is not a valid Int32 value" — and the
schema error short-circuits the business rules the scenario is actually
testing.
=#
@use Dates: now, UTC, year, month, format, Year, @dateformat_str

const NOW = now(UTC)
const today = format(NOW, dateformat"yyyy-mm-dd")
const stamp = format(NOW, dateformat"yyyy-mm-dd\THH:MM:SS.sss\Z")

"The Australian financial year containing `d`, labelled by the year it ends in."
financial_year(d) = month(d) >= 7 ? year(d) + 1 : year(d)

# Lump Sum E is a back payment for an earlier year, so it cannot be this one.
const lump_sum_fy = financial_year(NOW) - 1

fill_dates(xml) = replace(xml,
  # UTC, and it must be: VR.ATO.PAYEVNT.000194 checks it against arrival time.
  "<tns:MessageTimestampGenerationDt></tns:MessageTimestampGenerationDt>" =>
    "<tns:MessageTimestampGenerationDt>$stamp</tns:MessageTimestampGenerationDt>",
  "<tns:FinancialY></tns:FinancialY>" => "<tns:FinancialY>$lump_sum_fy</tns:FinancialY>",
  r"<tns:(\w+D)></tns:\1>" => SubstitutionString("<tns:\\1>$today</tns:\\1>"))

# A date in the previous financial year, for the rules that compare two of them.
const last_fy_date = format(NOW - Year(1), dateformat"yyyy-mm-dd")

"""
Two negative scenarios have a *date* as their trigger, so the blanket fill
above destroys the very thing they test by flattening it to today. Both
triggers are stated in the test case; each target is unique within its file.
"""
fixups(path, xml) = begin
  base = basename(path)
  if occursin("PAYEVNT-BULK-015_Submit_Request_01", base)
    # BULK-015: Payer Declaration Date (PAYEVNT38) in the future must return
    # CMN.ATO.PAYEVNT.000193. The suite's own case uses 1/1/2118.
    replace(xml, "<tns:SignatureD>$today</tns:SignatureD>" =>
                 "<tns:SignatureD>2118-01-01</tns:SignatureD>")
  elseif occursin("PAYEVNTEMP-BULK-016_Submit_Request_02", base)
    # BULK-016: the first child's ETP Payment Date (PAYEVNTEMP123) must fall in
    # a different financial year from the parent's Pay/Update Date (PAYEVNT69)
    # to return CMN.ATO.PAYEVNTEMP.000180.
    replace(xml, "<tns:IncomeD>$today</tns:IncomeD>" =>
                 "<tns:IncomeD>$last_fy_date</tns:IncomeD>")
  else
    xml
  end
end

payload(path) = Vector{UInt8}(fixups(path, fill_dates(read(path, String))))
