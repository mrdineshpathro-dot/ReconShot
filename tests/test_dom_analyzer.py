"""
Unit tests for DOM analysis, forms, endpoints, and secret token discovery.
"""

from reconshot.dom_analyzer import analyze_dom_content


def test_dom_forms_and_inputs():
    html = """
    <html>
      <body>
        <form action="/auth/login" method="POST">
          <input type="text" name="username" />
          <input type="password" name="password" />
          <input type="hidden" name="csrf" value="123" />
          <button type="submit">Sign In</button>
        </form>
        <form action="/upload" method="POST">
          <input type="file" name="doc" />
        </form>
      </body>
    </html>
    """
    dom = analyze_dom_content(html, "https://example.com")

    assert dom.forms_count == 2
    assert dom.has_login_form is True
    assert dom.has_password_field is True
    assert dom.has_file_upload is True
    assert "password" in dom.input_types
    assert "file" in dom.input_types


def test_dom_endpoints_and_secrets():
    html = """
    <script>
      const apiUser = "/api/v1/users/profile";
      const gql = "/graphql";
      const awsKey = "AKIAIOSFODNN7EXAMPLE";
      const gKey = "AIzaSyD-7p23456789012345678901234567890";
    </script>
    <!-- TODO: Remove debug credentials before prod deployment -->
    <a href="https://external-service.org/login">External</a>
    """
    dom = analyze_dom_content(html, "https://example.com")

    assert "/api/v1/users/profile" in dom.endpoints
    assert "/graphql" in dom.endpoints
    assert len(dom.potential_secrets) >= 2
    secret_types = [s["type"] for s in dom.potential_secrets]
    assert "AWS Access Key" in secret_types
    assert "Google API Key" in secret_types
    assert len(dom.comments) >= 1
    assert "TODO:" in dom.comments[0]
    assert "external-service.org" in dom.external_links
