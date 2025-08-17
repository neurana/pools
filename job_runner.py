#!/usr/bin/env python3
import os, sys, subprocess, importlib.util, textwrap
from pathlib import Path

def sh(*args, check=True):
    return subprocess.run(list(args), check=check)

def venv_bin(venv: Path, name: str) -> Path:
    return venv / ("Scripts" if os.name == "nt" else "bin") / name

def main():
    WORK = Path(os.environ.get("WORKSPACE", ".")).resolve()
    PORT = int(os.environ.get("PORT", "8000"))
    KIND = os.environ.get("KIND", "auto")

    WORK.mkdir(parents=True, exist_ok=True)
    VENV = WORK / ".venv"

    if not VENV.exists():
        sh(sys.executable, "-m", "venv", str(VENV))
    pip = venv_bin(VENV, "pip")
    req = WORK / "requirements.txt"
    if req.exists() and req.stat().st_size > 0:
        sh(str(pip), "install", "-r", str(req))

    env_file = WORK / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

    run_inner = WORK / "_run_inner.py"
    if not run_inner.exists():
        run_inner.write_text(textwrap.dedent(f"""
        import os, sys, importlib.util
        from pathlib import Path

        WORK = Path({repr(str(WORK))})
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
                print(f"[runner] import main failed: {{e}}", flush=True)
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
            print(f"[runner] starting kind={{kind}} port={{PORT}}", flush=True)
            if kind == "api":
                run_api()
            else:
                run_worker()

        if __name__ == "__main__":
            main()
        """), encoding="utf-8")

    py = venv_bin(VENV, "python")
    os.environ["PORT"] = str(PORT)
    os.execv(str(py), [str(py), str(run_inner)])

if __name__ == "__main__":
    main()
