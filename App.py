import os
import io
import sqlite3
import secrets
import string
from functools import wraps

import segno
from flask import (Flask, request, redirect, session, g, abort, Response,
                   render_template_string, url_for)
from werkzeug.middleware.proxy_fix import ProxyFix

DB_PATH = os.environ.get("DB_PATH", "data.db")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "change-me")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

SCHEMA = """
CREATE TABLE IF NOT EXISTS shops (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    review_url TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS visits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    shop_id INTEGER NOT NULL,
    source TEXT NOT NULL,
    ts TEXT DEFAULT CURRENT_TIMESTAMP,
    ua TEXT
);
CREATE INDEX IF NOT EXISTS idx_visits_shop ON visits(shop_id, ts);
"""


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    conn = g.pop("db", None)
    if conn:
        conn.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


init_db()


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper


def new_code():
    alphabet = string.ascii_lowercase + string.digits
    while True:
        code = "".join(secrets.choice(alphabet) for _ in range(6))
        if not db().execute("SELECT 1 FROM shops WHERE code=?", (code,)).fetchone():
            return code


# ---------- public: tap / scan redirect ----------

def track(code, source):
    shop = db().execute("SELECT * FROM shops WHERE code=?", (code,)).fetchone()
    if not shop:
        abort(404)
    db().execute(
        "INSERT INTO visits (shop_id, source, ua) VALUES (?,?,?)",
        (shop["id"], source, (request.headers.get("User-Agent") or "")[:200]),
    )
    db().commit()
    resp = redirect(shop["review_url"], code=302)
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/t/<code>")
def tap(code):
    return track(code, "nfc")


@app.route("/q/<code>")
def scan(code):
    return track(code, "qr")


@app.route("/qr/<code>.png")
@login_required
def qr_png(code):
    if not db().execute("SELECT 1 FROM shops WHERE code=?", (code,)).fetchone():
        abort(404)
    link = request.host_url.rstrip("/") + "/q/" + code
    buf = io.BytesIO()
    segno.make(link, error="m").save(buf, kind="png", scale=12, border=3)
    return Response(buf.getvalue(), mimetype="image/png")


# ---------- admin ----------

BASE = """
<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Review Tracker</title>
<style>
body{font-family:system-ui,sans-serif;margin:0;background:#f5f6f8;color:#1a1a1a}
.wrap{max-width:900px;margin:0 auto;padding:16px}
nav{background:#111;color:#fff;padding:12px 16px;display:flex;justify-content:space-between}
nav a{color:#fff;text-decoration:none;margin-left:12px}
.card{background:#fff;border-radius:10px;padding:16px;margin-bottom:16px;box-shadow:0 1px 3px #0001}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{padding:8px 6px;border-bottom:1px solid #eee;text-align:left}
input{width:100%;padding:10px;margin:6px 0 12px;border:1px solid #ccc;border-radius:6px;box-sizing:border-box}
button,.btn{background:#1a73e8;color:#fff;border:0;padding:10px 16px;border-radius:6px;text-decoration:none;display:inline-block;cursor:pointer}
code{background:#eee;padding:2px 6px;border-radius:4px;word-break:break-all}
.scroll{overflow-x:auto}
</style></head><body>
<nav><b>Review Tracker</b><span>{% if session.admin %}<a href="/">Dashboard</a><a href="/logout">Logout</a>{% endif %}</span></nav>
<div class="wrap">{{ body|safe }}</div></body></html>
"""


def page(tpl, **ctx):
    body = render_template_string(tpl, **ctx)
    return render_template_string(BASE, body=body)


@app.route("/login", methods=["GET", "POST"])
def login():
    err = ""
    if request.method == "POST":
        if secrets.compare_digest(request.form.get("password", ""), ADMIN_PASSWORD):
            session["admin"] = True
            return redirect("/")
        err = "Wrong password"
    return page("""
    <div class="card"><h3>Admin login</h3><p style="color:red">{{ err }}</p>
    <form method="post"><input type="password" name="password" placeholder="Password" autofocus>
    <button>Login</button></form></div>""", err=err)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


IST = "'+330 minutes'"


@app.route("/")
@login_required
def dashboard():
    rows = db().execute(f"""
        SELECT s.id, s.code, s.name,
          COALESCE(SUM(v.source='nfc'),0) AS nfc_total,
          COALESCE(SUM(v.source='qr'),0) AS qr_total,
          COALESCE(SUM(v.source='nfc' AND date(v.ts,{IST})=date('now',{IST})),0) AS nfc_today,
          COALESCE(SUM(v.source='qr' AND date(v.ts,{IST})=date('now',{IST})),0) AS qr_today,
          COALESCE(SUM(date(v.ts,{IST})>=date('now',{IST},'-6 days')),0) AS week
        FROM shops s LEFT JOIN visits v ON v.shop_id=s.id
        GROUP BY s.id ORDER BY s.id DESC""").fetchall()
    return page("""
    <div class="card"><h3>Add new shop</h3>
    <form method="post" action="/add">
      <input name="name" placeholder="Shop name" required>
      <input name="review_url" placeholder="Google review link (https://...)" required>
      <button>Create</button></form></div>
    <div class="card scroll"><h3>Shops</h3>
    <table><tr><th>Shop</th><th>Tap today</th><th>Scan today</th><th>7 days</th><th>Tap total</th><th>Scan total</th></tr>
    {% for r in rows %}
    <tr><td><a href="/shop/{{ r.id }}">{{ r.name }}</a></td>
    <td>{{ r.nfc_today }}</td><td>{{ r.qr_today }}</td><td>{{ r.week }}</td>
    <td>{{ r.nfc_total }}</td><td>{{ r.qr_total }}</td></tr>
    {% else %}<tr><td colspan="6">No shops yet.</td></tr>{% endfor %}
    </table></div>""", rows=rows)


def valid_url(u):
    return u.startswith("https://") or u.startswith("http://")


@app.route("/add", methods=["POST"])
@login_required
def add():
    name = request.form.get("name", "").strip()
    url = request.form.get("review_url", "").strip()
    if not name or not valid_url(url):
        return "Invalid name or link", 400
    db().execute("INSERT INTO shops (code,name,review_url) VALUES (?,?,?)",
                 (new_code(), name, url))
    db().commit()
    sid = db().execute("SELECT last_insert_rowid()").fetchone()[0]
    return redirect(f"/shop/{sid}")


@app.route("/shop/<int:sid>")
@login_required
def shop(sid):
    s = db().execute("SELECT * FROM shops WHERE id=?", (sid,)).fetchone()
    if not s:
        abort(404)
    base = request.host_url.rstrip("/")
    days = db().execute(f"""
        SELECT date(ts,{IST}) AS d,
               SUM(source='nfc') AS nfc, SUM(source='qr') AS qr
        FROM visits WHERE shop_id=? GROUP BY d ORDER BY d DESC LIMIT 14""",
        (sid,)).fetchall()
    return page("""
    <div class="card"><h3>{{ s.name }}</h3>
      <p><b>NFC link</b> (write this into the NFC card):<br><code>{{ base }}/t/{{ s.code }}</code></p>
      <p><b>QR link</b> (this is inside the QR image):<br><code>{{ base }}/q/{{ s.code }}</code></p>
      <img src="/qr/{{ s.code }}.png" width="220" alt="QR">
      <p><a class="btn" href="/qr/{{ s.code }}.png" download="{{ s.name }}-qr.png">Download QR</a></p>
    </div>
    <div class="card"><h3>Change Google review link</h3>
      <form method="post" action="/shop/{{ s.id }}/edit">
      <input name="name" value="{{ s.name }}" required>
      <input name="review_url" value="{{ s.review_url }}" required>
      <button>Save</button></form></div>
    <div class="card scroll"><h3>Last 14 days</h3>
      <table><tr><th>Date</th><th>Taps</th><th>Scans</th></tr>
      {% for d in days %}<tr><td>{{ d.d }}</td><td>{{ d.nfc }}</td><td>{{ d.qr }}</td></tr>
      {% else %}<tr><td colspan="3">No visits yet.</td></tr>{% endfor %}
      </table></div>""", s=s, base=base, days=days)


@app.route("/shop/<int:sid>/edit", methods=["POST"])
@login_required
def edit(sid):
    name = request.form.get("name", "").strip()
    url = request.form.get("review_url", "").strip()
    if not name or not valid_url(url):
        return "Invalid name or link", 400
    db().execute("UPDATE shops SET name=?, review_url=? WHERE id=?", (name, url, sid))
    db().commit()
    return redirect(f"/shop/{sid}")


if __name__ == "__main__":
    app.run(debug=True, port=5000)
