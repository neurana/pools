
import os, sys, importlib.util
from pathlib import Path

WORK = Path('/Users/brunohenrique/Local Documents/Neurana/API BUILDER/pool-local/userdata/user-123/secure-demo')
PORT = int(os.environ.get("PORT","8000"))
KIND = os.environ.get("KIND","auto")

def detect_api()->bool:
    try:
        code = (WORK/"main.py").read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False
    pats = ("FastAPI(", "Flask(", "quart.", "aiohttp.web.Application", "tornado.web", "Bottle(", "HTTPServer", "BaseHTTPRequestHandler")
    return any(p in code for p in pats)

def import_main():
    spec = importlib.util.spec_from_file_location("main", str(WORK/"main.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)  # type: ignore
    return m

def run_api():
    try:
        m = import_main()
        app = getattr(m, "app", None)
        if app is None:
            run_worker(); return
    except Exception as e:
        print(f"[runner] import main failed: {e}", flush=True)
        run_worker(); return
    try:
        import uvicorn
    except Exception:
        print("[runner] uvicorn não instalado no venv; caindo para worker.", flush=True)
        run_worker(); return
    uvicorn.run(app, host="0.0.0.0", port=PORT)

def run_worker():
    py = "python"
    os.execv(py, [py, str(WORK/"main.py")])

def main():
    os.chdir(str(WORK))
    kind = KIND
    if kind == "auto":
        kind = "api" if detect_api() else "worker"
    print(f"[runner] starting kind={kind} port={PORT}", flush=True)
    if kind == "api":
        run_api()
    else:
        run_worker()

if __name__ == "__main__":
    main()
