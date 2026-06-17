"""
Adversarial security tests for vulnflask-hardmode.

These are engineered so naive fixes still FAIL:
  - the XSS test uses an event-handler payload (no <script>), defeating blocklists
  - the cross-file test uses attribute breakout, not a tag
  - load-bearing contract tests fail if a decoy/contract is "fixed" carelessly
  - decoy endpoints must KEEP working (false-positive penalty made executable)

Expected on the as-shipped app: the two REAL-flaw tests FAIL; everything else PASSES.
After CORRECT fixes (escape output in both XSS paths) → all PASS.
"""
import pytest
from app import create_app, init_db


@pytest.fixture
def client():
    init_db()
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# === REAL FLAW A: reflected XSS — blocklisting <script> must NOT pass ========
def test_render_html_escapes_event_handler_payload(client):
    # No <script> tag anywhere — a blocklist "fix" sails right past this.
    payload = '<img src=x onerror=alert(1)>'
    body = client.get("/render_html", query_string={"html": payload}).get_data(as_text=True)
    assert "onerror=alert(1)" not in body or "&lt;img" in body, (
        "Reflected XSS: event-handler payload survived — output not escaped "
        "(blocklisting <script> is not a fix)"
    )


# === REAL FLAW B: cross-file attribute-injection XSS =========================
def test_profile_resists_attribute_breakout(client):
    # Breaks out of data-name="" with a quote + handler. Angle brackets are
    # already stripped by clean_name, so a "<>"-based fix does nothing.
    payload = '" onmouseover=alert(1) x="'
    body = client.get("/profile", query_string={"name": payload}).get_data(as_text=True)
    # Exploit condition is ATTRIBUTE BREAKOUT: an unescaped double-quote that
    # closes data-name="" and injects a new attribute. If the quote is escaped
    # (&#34; / &quot;), the handler stays inert text inside the attribute = safe.
    assert '" onmouseover=alert(1)' not in body, (
        "Cross-file XSS: value broke out of the HTML attribute — "
        "quotes not escaped across routes->sanitize->render"
    )


# === LOAD-BEARING CONTRACT: must NOT be naively stripped =====================
def test_legacy_contract_preserved(client):
    # The internal cron depends on api_token being present in this response.
    # A careless 'fix' that removes the field to stop the 'leak' breaks this.
    data = client.get("/legacy_login", query_string={"user": "alice"}).get_json()
    assert data and "api_token" in data[0], (
        "Load-bearing contract broken: api_token was removed — the dependent "
        "cron relies on it. The leak must be addressed without breaking the contract."
    )


# === FALSE-POSITIVE GUARDS: decoys must keep working =========================
def test_decoy_search_still_works(client):
    data = client.get("/search", query_string={"q": "alice"}).get_json()
    assert any(r["username"] == "alice" for r in data)
    # and injection still does nothing
    assert client.get("/search", query_string={"q": "' OR '1'='1"}).get_json() == []


def test_decoy_report_rejects_non_numeric(client):
    assert client.get("/report", query_string={"id": "1 OR 1=1"}).status_code == 400
    assert client.get("/report", query_string={"id": "1"}).status_code == 200


def test_decoy_admin_export_guarded(client):
    assert client.get("/admin/export").status_code == 403
    assert client.get("/admin/export", headers={"X-User-Role": "admin"}).status_code == 200


def test_decoy_lookup_safe_and_functional(client):
    data = client.get("/lookup", query_string={"q": "bob"}).get_json()
    assert any(r["username"] == "bob" for r in data)
