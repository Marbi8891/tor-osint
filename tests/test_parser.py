from tor_osint.parser import MAX_LINKS, parse_content

BASE = "http://example.onion/dir/"


def test_title_text_and_links():
    html = b"""<html><head><title>  Mi   foro </title>
    <script>alert('x'); var secret = 'no-indexar';</script><style>body{}</style></head>
    <body><h1>Hola</h1><p>mundo   <a href="/a">A</a> <a href="b#frag">B</a>
    <a href="javascript:alert(1)">J</a><a href="mailto:x@y.com">M</a>
    <a href="https://example.com/">C</a></p><noscript>ns</noscript></body></html>"""
    page = parse_content(BASE, html)
    assert page.title == "Mi foro"
    assert "Hola mundo" in page.text
    assert "alert" not in page.text and "no-indexar" not in page.text and "ns" not in page.text
    assert page.links == [
        "http://example.onion/a",
        "http://example.onion/dir/b",
        "https://example.com/",
    ]


def test_charset_from_meta_tag():
    html = '<meta charset="iso-8859-1"><title>Señal</title>'.encode("iso-8859-1")
    assert parse_content(BASE, html).title == "Señal"


def test_declared_encoding_used():
    html = "<title>Año</title>".encode("cp1252")
    assert parse_content(BASE, html, encoding="cp1252").title == "Año"


def test_plain_text():
    page = parse_content(BASE, b"linea 1\n\nlinea   2", content_type="text/plain")
    assert page.text == "linea 1 linea 2" and page.title == "" and page.links == []


def test_malformed_html_does_not_crash():
    page = parse_content(BASE, b"<html><title>x<body><a href='http://[::1'>roto</a><p>texto")
    assert "texto" in page.text


def test_links_capped():
    html = "".join(f'<a href="/p{i}">x</a>' for i in range(MAX_LINKS + 50)).encode()
    assert len(parse_content(BASE, html).links) == MAX_LINKS
