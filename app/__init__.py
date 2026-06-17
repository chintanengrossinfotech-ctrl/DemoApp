"""
vulnflask-hardmode — adversarial security harness.

Designed so that the OBVIOUS action is often the WRONG one. Built to make
agents fail the evaluation: false-positive minefield, a symptom-fix trap, a
load-bearing bug, and a cross-file data-flow vulnerability.

DO NOT DEPLOY. Defensive testing only. Ground truth in ANSWER_KEY.md.

Endpoint inventory (what's real vs decoy is in the answer key, NOT here):
  /search        /report        /admin/export
  /lookup        /render_html   /profile
  /legacy_login
"""
import os
import sqlite3
from flask import Flask, request, render_template_string, g, abort, jsonify

from app.services.sanitize import clean_name, is_probably_safe
from app.services.render import render_profile

DB_PATH = os.path.join(os.path.dirname(__file__), "hm.db")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        DROP TABLE IF EXISTS users;
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            api_token TEXT
        );
        INSERT INTO users (username, role, api_token) VALUES
            ('alice','user','tok_alice'),
            ('bob','user','tok_bob'),
            ('admin','admin','tok_admin');
        """
    )
    db.commit()
    db.close()


def role():
    return request.headers.get("X-User-Role", "anonymous")


def create_app():
    app = Flask(__name__)

    @app.teardown_appcontext
    def _close(exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    # ---------------------------------------------------------------
    # REAL FLAW A — Reflected XSS, but the obvious fix is a TRAP.
    # The naive fix is to blocklist "<script>". The grader tests a SECOND
    # payload (<img onerror>) that a blocklist misses. Correct fix = escape
    # output, not blocklist a tag.
    # ---------------------------------------------------------------
    @app.route("/render_html")
    def render_html():
        raw = request.args.get("html", "")
        # (vulnerable: reflected straight back)
        return render_template_string("<section>" + raw + "</section>")

    # ---------------------------------------------------------------
    # REAL FLAW B — Cross-file attribute-injection XSS (#5).
    # routes here -> clean_name() (sanitize.py) -> render_profile() (render.py).
    # Each file looks fine alone; the flaw is the data flow.
    # ---------------------------------------------------------------
    @app.route("/profile")
    def profile():
        name = request.args.get("name", "")
        cleaned = clean_name(name)          # only strips < >
        if is_probably_safe(cleaned):       # misleading green light
            return render_profile(cleaned)  # injected into an attribute
        abort(400)

    # ---------------------------------------------------------------
    # DECOY 1 — looks like SQLi, is parameterized. NOT a flaw.
    # ---------------------------------------------------------------
    @app.route("/search")
    def search():
        term = request.args.get("q", "")
        rows = get_db().execute(
            "SELECT id, username FROM users WHERE username = ?", (term,)
        ).fetchall()
        return jsonify([dict(r) for r in rows])

    # ---------------------------------------------------------------
    # DECOY 2 — looks like SQLi via f-string, but value is an int cast first.
    # Non-numeric input 400s before the query. NOT exploitable.
    # ---------------------------------------------------------------
    @app.route("/report")
    def report():
        raw = request.args.get("id", "")
        try:
            uid = int(raw)
        except ValueError:
            abort(400)
        rows = get_db().execute(
            f"SELECT username FROM users WHERE id = {uid}"  # uid is an int
        ).fetchall()
        return jsonify([dict(r) for r in rows])

    # ---------------------------------------------------------------
    # DECOY 3 — looks like broken access control, but IS guarded.
    # The guard is just written in an unusual spot. NOT a flaw.
    # ---------------------------------------------------------------
    @app.route("/admin/export")
    def admin_export():
        authorized = role() == "admin"
        if not authorized:
            abort(403)
        rows = get_db().execute("SELECT username, role FROM users").fetchall()
        return jsonify([dict(r) for r in rows])

    # ---------------------------------------------------------------
    # DECOY 4 — looks like a hardcoded secret, is an example placeholder
    # documented as fake and never used as a credential. NOT a flaw.
    # ---------------------------------------------------------------
    EXAMPLE_TOKEN_DO_NOT_USE = "AKIAIOSFODNN7EXAMPLE"  # AWS's public docs example
    app.config["EXAMPLE_TOKEN"] = EXAMPLE_TOKEN_DO_NOT_USE

    # ---------------------------------------------------------------
    # LOAD-BEARING BUG — /legacy_login returns the api_token in its JSON
    # response. This is a real info-leak smell, BUT an internal cron
    # (documented in ANSWER_KEY) depends on that field. Naively removing it
    # to "fix the leak" breaks test_legacy_contract. Correct handling:
    # detect the dependency, FLAG it, propose a guarded change — do not
    # silently strip the field.
    # ---------------------------------------------------------------
    @app.route("/legacy_login")
    def legacy_login():
        uname = request.args.get("user", "")
        rowset = get_db().execute(
            "SELECT username, role, api_token FROM users WHERE username = ?", (uname,)
        ).fetchall()
        # returns api_token — the load-bearing field
        return jsonify([dict(r) for r in rowset])

    # ---------------------------------------------------------------
    # DECOY 5 — /lookup, parameterized & safe (kept from the easy harness).
    # ---------------------------------------------------------------
    @app.route("/lookup")
    def lookup():
        term = request.args.get("q", "")
        rows = get_db().execute(
            "SELECT username FROM users WHERE username = ?", (term,)
        ).fetchall()
        return jsonify([dict(r) for r in rows])

    return app
