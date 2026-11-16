"""Local browser interface for Total Recon (standard library only)."""
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading
from urllib.parse import parse_qs, quote, urlparse
import webbrowser

import main

HOST = "127.0.0.1"
PORT = 8000

STYLES = """
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#121a2e;--line:#25324d;--text:#eef3ff;--muted:#9aabc8;--accent:#6ee7c2;--blue:#83a7ff}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 50% -20%,#233456 0,transparent 55%),var(--bg);color:var(--text);font:15px/1.55 system-ui,Segoe UI,sans-serif}
main{max-width:1100px;margin:45px auto;padding:0 22px}.top{display:flex;align-items:end;justify-content:space-between;gap:16px;margin-bottom:25px}.eyebrow{color:var(--accent);font-size:12px;font-weight:700;letter-spacing:.14em;text-transform:uppercase}h1{font-size:clamp(32px,5vw,52px);line-height:1.05;margin:8px 0}p{color:var(--muted);margin:8px 0}.badge{border:1px solid var(--line);border-radius:999px;padding:7px 12px;color:var(--muted);white-space:nowrap}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:15px}.card,.results{background:linear-gradient(145deg,#17213a,var(--panel));border:1px solid var(--line);border-radius:17px;padding:21px;box-shadow:0 14px 35px #0002}.card h2{font-size:18px;margin:0 0 3px}.number{color:var(--blue);font-size:12px;font-weight:700;letter-spacing:.1em}.field{display:block;margin-top:15px;color:#c7d3e9;font-size:13px}.field input,.field textarea{display:block;width:100%;margin-top:6px;border:1px solid #34425e;border-radius:9px;background:#0b1222;color:var(--text);padding:11px 12px;font:inherit;outline:none}.field input:focus,.field textarea:focus{border-color:var(--accent)}textarea{min-height:116px;resize:vertical}.hint{font-size:12px;margin-top:5px}button{margin-top:17px;border:0;border-radius:9px;background:var(--accent);color:#0a1c20;font-weight:750;padding:10px 15px;font:inherit;cursor:pointer}button:hover{filter:brightness(1.08)}.results{margin-top:18px;border-color:#355744}.results h2{margin:0 0 7px;font-size:18px}.output{white-space:pre-wrap;overflow-wrap:anywhere;color:#d6e5f7;max-height:420px;overflow:auto}.output a{color:var(--accent)}.notice{font-size:12px;margin-top:20px}.full{grid-column:1/-1}
@media(max-width:720px){main{margin:25px auto}.top{align-items:start;flex-direction:column}.grid{grid-template-columns:1fr}.full{grid-column:auto}}
</style>
"""


def page(result_title="", result="", links=None, error=False):
    result_html = ""
    if result_title:
        content = escape(str(result))
        if links:
            content += "\n" + "\n".join(
                f'<a href="{escape(url, quote=True)}" target="_blank" rel="noopener">{escape(label)}</a>'
                for label, url in links
            )
        result_html = (
            f'<section class="results" aria-live="polite"><h2>{escape(result_title)}</h2>'
            f'<div class="output">{content}</div></section>'
        )
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Total Recon</title>{STYLES}</head>
<body><main><header class="top"><div><div class="eyebrow">Local security toolkit</div>
<h1>Total Recon</h1><p>Five focused recon tools, running on your machine.</p></div><span class="badge">v{main.VERSION} · localhost</span></header>
{result_html}<section class="grid">
<article class="card"><div class="number">TOOL 01</div><h2>HTTP status checker</h2><p>Check the response status for a URL.</p>
<form method="post"><input type="hidden" name="action" value="http"><label class="field">URL<input name="url" placeholder="https://example.com" required></label><button>Check status</button></form></article>
<article class="card"><div class="number">TOOL 02</div><h2>Subdomain scanner</h2><p>Try entries from the included subdomain wordlist.</p>
<form method="post"><input type="hidden" name="action" value="subdomains"><label class="field">Your domain<input name="domain" placeholder="example.com" required></label><label class="field">Entries to scan<input type="number" name="limit" value="500" min="1" max="{main.MAX_SCAN_LIMIT}"></label><button>Scan subdomains</button></form></article>
<article class="card"><div class="number">TOOL 03</div><h2>Directory scanner</h2><p>Check common paths from the included directory wordlist.</p>
<form method="post"><input type="hidden" name="action" value="directories"><label class="field">Your domain<input name="domain" placeholder="example.com" required></label><label class="field">Entries to scan<input type="number" name="limit" value="500" min="1" max="{main.MAX_SCAN_LIMIT}"></label><button>Scan directories</button></form></article>
<article class="card"><div class="number">TOOL 04</div><h2>Google dork links</h2><p>Build search links scoped to a domain. Links open when clicked.</p>
<form method="post"><input type="hidden" name="action" value="dorks"><label class="field">Your domain<input name="domain" placeholder="example.com" required></label><label class="field">Queries to create<input type="number" name="limit" value="5" min="1" max="25"></label><button>Build links</button></form></article>
<article class="card full"><div class="number">TOOL 05</div><h2>JWT signature checker</h2><p>Check whether a signing secret in your wordlist matches your own HS/RS token.</p>
<form method="post"><input type="hidden" name="action" value="jwt"><label class="field">JWT token<textarea name="token" placeholder="Paste your three-part JWT" required></textarea></label><label class="field">Algorithm<input name="algorithm" value="HS256" placeholder="HS256" required></label><label class="field">Candidate secrets, one per line<textarea name="secrets" placeholder="demo-secret-123&#10;another-candidate" required></textarea><span class="hint">Only candidate secrets you provide are checked; contents are not saved.</span></label><button>Check signature</button></form></article>
</section><p class="notice">Use only on systems and tokens you own or are authorized to assess. Scans are capped at {main.MAX_SCAN_LIMIT} entries.</p></main></body></html>'''


class Handler(BaseHTTPRequestHandler):
    def send_html(self, body, status=200):
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if urlparse(self.path).path != "/":
            self.send_html("Not found", 404)
            return
        self.send_html(page())

    def do_POST(self):
        if urlparse(self.path).path != "/":
            self.send_html("Not found", 404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 1_000_000:
                raise ValueError("Request is too large.")
            form = parse_qs(self.rfile.read(length).decode("utf-8"), keep_blank_values=True)
            get = lambda key, default="": form.get(key, [default])[0].strip()
            action = get("action")
            if action == "http":
                url, status = main.get_http_status(get("url"))
                title, result, links = "HTTP status", f"{url} returned HTTP {status}.", None
            elif action == "subdomains":
                limit = max(1, min(int(get("limit", "500")), main.MAX_SCAN_LIMIT))
                words = main._read_lines("2m-subdomains.txt", limit=limit)
                if words is None:
                    raise ValueError("Could not read the included subdomain wordlist.")
                candidates, found = main.scan_subdomains(get("domain"), words, limit)
                title = "Subdomain scan results"
                result = "\n".join(f"HTTP {status} · {host}" for status, host in found) or f"No responding subdomains in the first {len(candidates)} entries."
                links = None
            elif action == "directories":
                limit = max(1, min(int(get("limit", "500")), main.MAX_SCAN_LIMIT))
                words = main._read_lines("dirbig.txt", limit=limit)
                if words is None:
                    raise ValueError("Could not read the included directory wordlist.")
                candidates, found = main.scan_directories(get("domain"), words, limit)
                title = "Directory scan results"
                result = "\n".join(f"HTTP {status} · {url}" for status, url in found) or f"No matching paths in the first {len(candidates)} entries."
                links = None
            elif action == "dorks":
                dorks = main._read_lines("gdorks.txt")
                if dorks is None:
                    raise ValueError("Could not read the included dork list.")
                limit = max(1, min(int(get("limit", "5")), 25))
                urls = main.build_google_dork_urls(get("domain"), dorks, limit)
                title, result = "Google search links", f"Created {len(urls)} links. Open only the searches you want to review."
                links = [(f"Search {index + 1}: {url}", url) for index, url in enumerate(urls)]
            elif action == "jwt":
                token, algorithm, secrets = get("token"), get("algorithm"), get("secrets").splitlines()
                secret = main.find_jwt_secret(token, algorithm, secrets)
                title = "JWT signature check"
                result = f"Matching secret: {secret}" if secret is not None else "No matching secret was found in the candidates you entered."
                links = None
            else:
                raise ValueError("Choose a tool and try again.")
            self.send_html(page(title, result, links))
        except (ValueError, TypeError) as exc:
            self.send_html(page("Could not complete that check", str(exc)), 400)
        except Exception as exc:
            self.send_html(page("Operation failed", str(exc)), 500)

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {fmt % args}")


def serve(open_browser=True):
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True
    url = f"http://{HOST}:{PORT}"
    print(f"Total Recon is available at {url}")
    if open_browser:
        threading.Timer(0.7, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    serve()
