@use "../XMLSig.jl" c14n
@use EzXML: parsexml, root
@use Test...

@testset "exclusive c14n" begin
  # unused namespaces dropped, comments stripped, attrs sorted, empty tags expanded
  doc = parsexml("""<a xmlns:u="urn:u"><b z="1" a="2" xmlns:v="urn:v">hi<!--c--></b><c/></a>""")
  @test c14n(doc) == """<a><b a="2" z="1">hi</b><c></c></a>"""
  # visibly-used namespace kept
  doc2 = parsexml("""<a xmlns:u="urn:u"><u:b/></a>""")
  @test c14n(doc2) == """<a><u:b xmlns:u="urn:u"></u:b></a>"""
  # subtree canonicalization in document context
  doc3 = parsexml("""<r xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:X/></ds:SignedInfo></r>""")
  @test c14n(doc3, "//ds:SignedInfo") == """<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X></ds:X></ds:SignedInfo>"""
  # subtree selection by wsu:Id predicate
  wsu = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
  doc4 = parsexml("""<r xmlns:wsu="$wsu"><x wsu:Id="a">1</x><x wsu:Id="b">2</x></r>""")
  @test c14n(doc4, """//*[@wsu:Id="b"]""") == """<x xmlns:wsu="$wsu" wsu:Id="b">2</x>"""
end
