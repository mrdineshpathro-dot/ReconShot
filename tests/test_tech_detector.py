"""
Unit tests for technology stack fingerprinting and favicon hashing.
"""

from reconshot.tech_detector import calculate_favicon_hash, detect_technologies


def test_detect_web_servers_and_cdn():
    headers = {
        "Server": "nginx/1.24.0",
        "CF-RAY": "8823482348234-SEA",
        "Via": "1.1 cloudfront.net",
    }
    techs = detect_technologies(headers=headers)
    names = [t.name for t in techs]

    assert "Nginx" in names
    assert "Cloudflare" in names
    assert "AWS CloudFront" in names


def test_detect_frontend_frameworks():
    html = """
    <!DOCTYPE html>
    <html>
      <head>
        <link rel="stylesheet" href="/_next/static/css/styles.css">
      </head>
      <body class="flex flex-col items-center justify-center p-4">
        <div id="__next" data-reactroot="">
          <h1 class="text-3xl font-bold">Welcome to Next.js App</h1>
        </div>
      </body>
    </html>
    """
    techs = detect_technologies(html_content=html)
    names = [t.name for t in techs]

    assert "Next.js" in names
    assert "React" in names
    assert "Tailwind CSS" in names


def test_detect_cms_wordpress():
    html = '<meta name="generator" content="WordPress 6.4.2" /><link rel="stylesheet" href="/wp-content/themes/theme.css" />'
    techs = detect_technologies(html_content=html)
    names = [t.name for t in techs]

    assert "WordPress" in names
    wp = next(t for t in techs if t.name == "WordPress")
    assert wp.version == "6.4.2"


def test_calculate_favicon_hash():
    sample_ico = b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x18\x00\x68\x00\x00\x00"
    hashes = calculate_favicon_hash(sample_ico)

    assert "shodan_hash" in hashes
    assert "md5" in hashes
    assert "sha256" in hashes
    assert len(hashes["md5"]) == 32
