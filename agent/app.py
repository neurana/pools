# agent/app.py
import os, re, json, asyncio, signal, time, threading, logging, sys, socket
import shutil, stat, subprocess
from pathlib import Path
from typing import Literal, Optional, Dict, Tuple, Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse, StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Observabilidade
from prometheus_fastapi_instrumentator import Instrumentator
from prometheus_client import Counter, Gauge, Histogram
from pythonjsonlogger import jsonlogger

# Criptografia de secrets em repouso
from cryptography.fernet import Fernet

# ======================== Config loader (TOML + ENV) ====================== #
try:
    from agent.config import CFG
except Exception:
    from config import CFG  # type: ignore

# ======================== Configuração base =============================== #

BASE = Path(CFG.agent.base_dir).resolve()
BASE.mkdir(parents=True, exist_ok=True)

SECRETS_DIR = Path(CFG.agent.secrets_dir).resolve()
SECRETS_DIR.mkdir(parents=True, exist_ok=True)

API_PORT_START = CFG.skills.api_port_start
API_PORT_END   = CFG.skills.api_port_end

# Auto-restart defaults (podem ser sobrescritos por payload por-skill)
RESTART_MODE_DEFAULT = CFG.restart_defaults.mode              # "always"|"on-failure"|"never"
RESTART_MAX_RESTARTS = CFG.restart_defaults.max_restarts
RESTART_WINDOW_SEC   = CFG.restart_defaults.window_seconds
RESTART_MIN_UPTIME   = CFG.restart_defaults.min_uptime
BACKOFF_START_SEC    = CFG.restart_defaults.backoff_seconds
BACKOFF_FACTOR       = CFG.restart_defaults.backoff_factor
BACKOFF_MAX_SEC      = CFG.restart_defaults.backoff_max

# Rotação de logs
LOG_ROTATE_MAX_BYTES = CFG.observability.log_rotate_max_bytes
LOG_ROTATE_BACKUPS   = CFG.observability.log_rotate_backups

# Padrão do manifesto de export/import
EXPORT_SCHEMA = "pool-skill-manifest.v1"

# ============================ Logging (JSON) ============================== #

root_logger = logging.getLogger()
root_logger.setLevel(getattr(logging, CFG.agent.log_level.upper(), logging.INFO))
_handler = logging.StreamHandler(sys.stdout)

if CFG.agent.json_logs:
    _handler.setFormatter(jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(message)s'))
else:
    _handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

root_logger.handlers = [_handler]
log = logging.getLogger("pool-agent")

# ==================== Chave mestra para secrets (Fernet) ================== #

_master = CFG.security.secrets_master
if not _master:
    log.error("Chave Fernet ausente — configure em config/agent.toml (security.secrets_master ou secrets_master_file) ou via ENV.")
    raise RuntimeError("AGENT_SECRETS_MASTER/FILE é obrigatório para persistência segura de secrets.")
FERNET = Fernet(_master)

# ========================= Estruturas de dados ============================ #

class RestartPolicy(BaseModel):
    mode: Literal["always", "on-failure", "never"] = Field(default=RESTART_MODE_DEFAULT)
    max_restarts: int = Field(default=RESTART_MAX_RESTARTS)
    window_seconds: int = Field(default=RESTART_WINDOW_SEC)
    min_uptime: float = Field(default=RESTART_MIN_UPTIME)
    backoff_seconds: float = Field(default=BACKOFF_START_SEC)
    backoff_factor: float = Field(default=BACKOFF_FACTOR)
    backoff_max: float = Field(default=BACKOFF_MAX_SEC)

class ProcInfo(BaseModel):
    pid: int
    port: Optional[int]
    kind: Literal["api","worker"]
    stdout: Path
    stderr: Path
    started_at: float
    restarts: int = 0
    last_exit: Optional[int] = None
    policy: RestartPolicy = Field(default_factory=RestartPolicy)

# (uid,name) -> ProcInfo
PROCS: Dict[Tuple[str,str], ProcInfo] = {}

# (uid,name) -> subprocess.Popen (guardado à parte)
HANDLES: Dict[Tuple[str,str], subprocess.Popen] = {}

# (uid,name) -> file handles (stdout_fp, stderr_fp) para fechar ao parar/deletar
HANDLES_FDS: Dict[Tuple[str,str], tuple] = {}

# (uid,name) -> spec de relançamento
class LaunchSpec(BaseModel):
    uid: str
    name: str
    kind: Literal["api","worker"]
    wdir: Path
    port: Optional[int]
    policy: RestartPolicy

SPECS: Dict[Tuple[str,str], LaunchSpec] = {}

# Controle de restart
RESTART_HISTORY: Dict[Tuple[str,str], list] = {}  # timestamps dos restarts
BACKOFF_NEXT_TS: Dict[Tuple[str,str], float] = {} # quando pode tentar de novo
QUARANTINE_UNTIL: Dict[Tuple[str,str], float] = {}# se excedeu limite
MANUAL_STOP: set[Tuple[str,str]] = set()          # stop manual => não religar
DELETING: set[Tuple[str,str]] = set()             # em deleção: monitor não religa

# ============================== Métricas ================================== #

m_skill_starts   = Counter("pool_skill_starts_total",   "Starts de skills", ["uid","skill","kind"])
m_skill_restarts = Counter("pool_skill_restarts_total", "Restarts automáticos", ["uid","skill","kind","reason"])
m_skill_crashes  = Counter("pool_skill_crashes_total",  "Crashes detectados", ["uid","skill","kind"])
m_skill_stops    = Counter("pool_skill_stops_total",    "Stops manuais", ["uid","skill"])
m_skill_running  = Gauge  ("pool_skill_running",        "Skills rodando (gauge)", ["uid","skill","kind"])
m_restart_backoff= Gauge  ("pool_skill_restart_backoff_seconds", "Backoff atual", ["uid","skill"])

m_uptime = Histogram("pool_skill_uptime_seconds",
                     "Uptime observado até parada/crash",
                     buckets=(1,3,5,10,30,60,120,300,600,1800,3600))

# ============================== FastAPI =================================== #

app = FastAPI(title="Pool Agent (no-docker)", version="dev")

# Prometheus /metrics + métricas de requests (opcional)
if CFG.observability.prometheus_metrics:
    Instrumentator().instrument(app).expose(app)

# CORS opcional
if CFG.agent.cors_allow_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CFG.agent.cors_allow_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Request-ID + log básico de requisição
@app.middleware("http")
async def add_request_id_and_log(request: Request, call_next):
    rid = request.headers.get("x-request-id") or os.urandom(8).hex()
    start = time.time()
    resp = await call_next(request)
    dur = time.time() - start
    resp.headers["x-request-id"] = rid
    log.info("http_request", extra={
        "rid": rid, "method": request.method, "path": str(request.url.path),
        "status": resp.status_code, "duration_ms": round(dur*1000,2)
    })
    return resp

# ========================= Utilidades internas ============================ #

def slug(s:str)->str:
    return re.sub(r"[^a-z0-9\-]+","-", s.lower()).strip("-")

def workspace(uid:str, name:str) -> Path:
    return BASE/slug(uid)/slug(name)

def detect_api_from_code(code:str)->bool:
    pats = ("FastAPI(", "Flask(", "quart.", "aiohttp.web.Application",
            "tornado.web", "Bottle(", "HTTPServer", "BaseHTTPRequestHandler")
    return any(p in code for p in pats)

def find_free_port(start=API_PORT_START, end=API_PORT_END)->int:
    for p in range(start, end):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.1)
            if s.connect_ex(("127.0.0.1", p)) != 0:
                return p
    raise RuntimeError("no free port available")

def _rotate_log_if_needed(path: Path, max_bytes: int = LOG_ROTATE_MAX_BYTES, backups: int = LOG_ROTATE_BACKUPS):
    try:
        if path.exists() and path.stat().st_size >= max_bytes:
            for i in range(backups, 0, -1):
                src = path.with_suffix(path.suffix + ("" if i==1 else f".{i-1}"))
                dst = path.with_suffix(path.suffix + f".{i}")
                if src.exists():
                    try: dst.unlink()
                    except Exception: pass
                    try: src.replace(dst)
                    except Exception: pass
            try: path.unlink()
            except Exception: pass
            path.touch()
    except Exception as e:
        log.warning("log_rotate_error", extra={"path": str(path), "err": str(e)})

def sys_exe()->str:
    return os.environ.get("PYTHON", sys.executable)

def _on_rm_error(func, path, exc_info):
    try:
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
    except Exception:
        pass
    try:
        if os.path.isdir(path) and not os.path.islink(path):
            os.rmdir(path)
        else:
            os.remove(path)
    except Exception:
        pass

def _force_rmtree(path: Path):
    if path.exists():
        shutil.rmtree(path, onerror=_on_rm_error)

# =================== Persistência criptografada de secrets ================= #

def _secret_path(uid:str, name:str) -> Path:
    return SECRETS_DIR / f"{slug(uid)}__{slug(name)}.enc"

def set_skill_secrets(uid:str, name:str, secrets:dict[str,str]):
    payload = json.dumps(secrets or {}, ensure_ascii=False).encode("utf-8")
    data = FERNET.encrypt(payload)
    _secret_path(uid, name).write_bytes(data)
    log.info("secrets_set", extra={"uid":uid, "skill":name, "keys":sorted((secrets or {}).keys())})

def get_skill_secrets(uid:str, name:str) -> dict[str,str]:
    p = _secret_path(uid, name)
    if not p.exists() or p.stat().st_size == 0:
        return {}
    try:
        raw = FERNET.decrypt(p.read_bytes())
        return json.loads(raw.decode("utf-8"))
    except Exception as e:
        log.error("secret_load_error", extra={"uid":uid, "skill":name, "err": str(e)})
        return {}

# ============================ Modelos REST ================================= #

class SkillIn(BaseModel):
    name: str
    code: str = ""
    requirements: str = ""
    secrets: dict[str,str] = {}
    kind: Literal["api","worker","auto"] = "auto"
    apt_packages: list[str] = []
    mem: Optional[str] = None
    cpus: Optional[float] = None
    code_url: Optional[str] = None

    restart_mode: Optional[Literal["always","on-failure","never"]] = None
    restart_max_restarts: Optional[int] = None
    restart_window_seconds: Optional[int] = None
    restart_min_uptime: Optional[float] = None
    restart_backoff_seconds: Optional[float] = None
    restart_backoff_factor: Optional[float] = None
    restart_backoff_max: Optional[float] = None

class SkillInBody(SkillIn):
    pass

class ImportIn(BaseModel):
    manifest: Dict[str, Any]
    name: Optional[str] = None
    secrets: Optional[Dict[str, str]] = None
    start: bool = True
    overwrite: bool = False

# ============================ Lifecycle helpers =========================== #

def write_files(uid:str, name:str, code:str, requirements:str) -> Path:
    wdir = workspace(uid, name)
    wdir.mkdir(parents=True, exist_ok=True)
    (wdir/"main.py").write_text(code or "", encoding="utf-8")
    (wdir/"requirements.txt").write_text(requirements or "", encoding="utf-8")
    (wdir/"_logs").mkdir(exist_ok=True)
    return wdir

def _kill_process_group(proc: subprocess.Popen):
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass
    try:
        proc.wait(timeout=5)
    except Exception:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except Exception:
            try: proc.kill()
            except Exception: pass
        try:
            proc.wait(timeout=2)
        except Exception:
            pass

def stop_proc(uid:str, name:str, manual: bool = True):
    key = (slug(uid), slug(name))
    info = PROCS.get(key)

    if manual:
        MANUAL_STOP.add(key)
        m_skill_stops.labels(uid=uid, skill=name).inc()

    if info:
        try:
            m_uptime.observe(max(0.0, time.time() - info.started_at))
        except Exception:
            pass

    h = HANDLES.pop(key, None)

    if h:
        _kill_process_group(h)

    fds = HANDLES_FDS.pop(key, None)
    if fds:
        for fp in fds:
            try: fp.close()
            except Exception: pass

    PROCS.pop(key, None)
    if info:
        m_skill_running.labels(uid=uid, skill=name, kind=info.kind).set(0)

def start_proc(uid:str, name:str, kind:str, wdir:Path, port:Optional[int], policy: RestartPolicy) -> ProcInfo:
    logdir = wdir / "_logs"
    logdir.mkdir(exist_ok=True)

    stdout = (logdir/"stdout.log")
    stderr = (logdir/"stderr.log")
    _rotate_log_if_needed(stdout)
    _rotate_log_if_needed(stderr)
    out_f = open(stdout, "a", encoding="utf-8", buffering=1)
    err_f = open(stderr, "a", encoding="utf-8", buffering=1)

    env = os.environ.copy()
    env["WORKSPACE"] = str(wdir)
    if port: env["PORT"] = str(port)
    env["KIND"] = kind

    secrets = get_skill_secrets(uid, name)
    if secrets:
        env.update(secrets)

    runner = Path(__file__).parent.parent / "job_runner.py"

    proc = subprocess.Popen(
        [sys_exe(), str(runner)],
        cwd=str(wdir),
        env=env,
        stdout=out_f,
        stderr=err_f,
        start_new_session=True,
    )

    info = ProcInfo(
        pid=proc.pid, port=port, kind=kind,
        stdout=stdout, stderr=stderr,
        started_at=time.time(),
        policy=policy
    )
    key = (slug(uid), slug(name))
    PROCS[key] = info
    HANDLES[key] = proc
    HANDLES_FDS[key] = (out_f, err_f)
    SPECS[key] = LaunchSpec(uid=uid, name=name, kind=kind, wdir=wdir, port=port, policy=policy)
    BACKOFF_NEXT_TS.pop(key, None)
    MANUAL_STOP.discard(key)
    m_skill_starts.labels(uid=uid, skill=name, kind=kind).inc()
    m_skill_running.labels(uid=uid, skill=name, kind=kind).set(1)

    log.info("skill_started", extra={"uid": uid, "skill": name, "kind": kind, "pid": proc.pid, "port": port})
    return info

def maybe_restart(key: Tuple[str,str], exit_code: Optional[int]):
    if key in MANUAL_STOP:
        MANUAL_STOP.discard(key)
        return

    spec = SPECS.get(key)
    if not spec:
        return
    uid, name = spec.uid, spec.name
    policy = spec.policy
    kind = spec.kind

    if policy.mode == "never":
        return
    if policy.mode == "on-failure" and (exit_code == 0 or exit_code is None):
        return

    now = time.time()
    hist = RESTART_HISTORY.setdefault(key, [])
    hist = [t for t in hist if now - t <= policy.window_seconds]
    if len(hist) >= policy.max_restarts:
        QUARANTINE_UNTIL[key] = now + max(policy.backoff_seconds, 30.0)
        RESTART_HISTORY[key] = hist
        log.error("skill_quarantine", extra={"uid": uid, "skill": name, "restarts_in_window": len(hist)})
        return

    next_ts = BACKOFF_NEXT_TS.get(key, 0.0)
    if now < next_ts:
        return

    port = spec.port
    if kind == "api":
        try:
            port = find_free_port()
        except Exception:
            pass

    info = start_proc(uid, name, kind, spec.wdir, port, policy)
    info.restarts += 1
    RESTART_HISTORY[key] = hist + [now]
    reason = "exit0" if exit_code == 0 else "crash"
    m_skill_restarts.labels(uid=uid, skill=name, kind=kind, reason=reason).inc()

    cur = policy.backoff_seconds
    nxt = min(cur * policy.backoff_factor, policy.backoff_max)
    BACKOFF_NEXT_TS[key] = now + cur
    m_restart_backoff.labels(uid=uid, skill=name).set(cur)
    spec.policy.backoff_seconds = nxt

# ===================== Helpers de manifesto (export/import) ================ #

def _read_text_safe(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        return ""

def _merge_restart_policy_from_dict(base: RestartPolicy, d: Optional[Dict[str, Any]]) -> RestartPolicy:
    if not d:
        return base
    merged = RestartPolicy(**base.model_dump())
    for field in ["mode","max_restarts","window_seconds","min_uptime",
                  "backoff_seconds","backoff_factor","backoff_max"]:
        if field in d and d[field] is not None:
            setattr(merged, field, d[field])
    return merged

def build_manifest(uid: str, name: str) -> Dict[str, Any]:
    uid_s, name_s = slug(uid), slug(name)
    wdir = workspace(uid_s, name_s)

    if not (wdir / "main.py").exists():
        raise HTTPException(404, "Skill não encontrada")

    code = _read_text_safe(wdir / "main.py")
    requirements = _read_text_safe(wdir / "requirements.txt")

    spec = SPECS.get((uid_s, name_s))
    if spec:
        kind = spec.kind
        policy = spec.policy.model_dump()
    else:
        kind = "api" if detect_api_from_code(code) else "worker"
        policy = RestartPolicy().model_dump()

    secret_keys = sorted(get_skill_secrets(uid_s, name_s).keys())

    manifest = {
        "schema": EXPORT_SCHEMA,
        "name": name_s,
        "kind": kind,
        "code": code,
        "requirements": requirements,
        "restart_policy": policy,
        "secret_keys": secret_keys,
        "meta": {
            "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "agent_version": "dev-nodocker",
            "python": sys_exe(),
            "api_port_range": [API_PORT_START, API_PORT_END],
        },
    }
    return manifest

# ============================== Monitor loop =============================== #

RUN_MONITOR = True

def monitor_loop():
    while RUN_MONITOR:
        try:
            now = time.time()
            for k, until in list(QUARANTINE_UNTIL.items()):
                if now >= until:
                    QUARANTINE_UNTIL.pop(k, None)
                    RESTART_HISTORY.pop(k, None)

            for key, proc in list(HANDLES.items()):
                if key in DELETING:
                    ret = proc.poll()
                    if ret is not None:
                        PROCS.pop(key, None)
                        HANDLES.pop(key, None)
                        HANDLES_FDS.pop(key, None)
                    continue

                ret = proc.poll()
                if ret is None:
                    continue
                uid, name = key
                info = PROCS.pop(key, None)
                HANDLES.pop(key, None)
                HANDLES_FDS.pop(key, None)
                m_skill_running.labels(uid=uid, skill=name, kind=(info.kind if info else "api")).set(0)
                if info:
                    m_uptime.observe(max(0.0, time.time() - info.started_at))
                    info.last_exit = ret
                    if ret != 0:
                        m_skill_crashes.labels(uid=uid, skill=name, kind=info.kind).inc()
                log.warning("skill_exited", extra={"uid": uid, "skill": name, "exit_code": ret})

                if key not in QUARANTINE_UNTIL:
                    maybe_restart(key, ret)
        except Exception as e:
            log.error("monitor_error", extra={"err": str(e)})
        time.sleep(0.8)

@app.on_event("startup")
def _startup():
    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()
    log.info("agent_started", extra={"mode":"dev-nodocker"})

@app.on_event("shutdown")
def _shutdown():
    global RUN_MONITOR
    RUN_MONITOR = False
    log.info("agent_stopping")

# ------------------------------ URL helper -------------------------------- #

def skill_public_url(port: Optional[int]) -> Optional[str]:
    if not port:
        return None
    if CFG.agent.public_base_url:
        base = CFG.agent.public_base_url.rstrip("/")
        return f"{base}:{port}/"
    # Em Docker, normalmente mapeamos portas pro host. localhost funciona bem.
    return f"http://localhost:{port}/"

# ============================== Rotas HTTP ================================= #

@app.get("/health")
def health():
    running = len(HANDLES)
    return {
        "ok": True,
        "python": sys_exe(),
        "skills_running": running,
        "quarantined": [list(k) for k in QUARANTINE_UNTIL.keys()],
    }

@app.get("/users/{uid}/skills")
def list_skills(uid:str):
    uid = slug(uid)
    items = []
    base = BASE/uid
    if base.exists():
        for path in base.glob("*"):
            if not path.is_dir():
                continue
            if not (path / "main.py").exists():
                continue
            name = path.name
            key = (uid,name)
            info = PROCS.get(key)
            is_api = bool(info and info.kind=="api")
            url = skill_public_url(info.port) if (info and info.port) else None
            status = "running" if info else "stopped"
            restarts = info.restarts if info else 0
            items.append({"name": name, "status": status, "is_api": is_api, "url": url, "restarts": restarts})
    return items

@app.post("/users/{uid}/skills")
def upsert(uid:str, body: SkillInBody):
    import requests
    uid = slug(uid)

    code = body.code
    if body.code_url and not code:
        r = requests.get(body.code_url, timeout=20)
        r.raise_for_status()
        code = r.text

    kind = body.kind
    if kind == "auto":
        kind = "api" if detect_api_from_code(code) else "worker"

    pol = RestartPolicy(
        mode = body.restart_mode or RESTART_MODE_DEFAULT,
        max_restarts = body.restart_max_restarts or RESTART_MAX_RESTARTS,
        window_seconds = body.restart_window_seconds or RESTART_WINDOW_SEC,
        min_uptime = body.restart_min_uptime or RESTART_MIN_UPTIME,
        backoff_seconds = body.restart_backoff_seconds or BACKOFF_START_SEC,
        backoff_factor = body.restart_backoff_factor or BACKOFF_FACTOR,
        backoff_max = body.restart_backoff_max or BACKOFF_MAX_SEC,
    )

    wdir = write_files(uid, body.name, code, body.requirements)

    if body.secrets:
        set_skill_secrets(uid, body.name, body.secrets)

    stop_proc(uid, body.name, manual=True)

    port = find_free_port() if kind=="api" else None
    info = start_proc(uid, body.name, kind, wdir, port, pol)
    url = skill_public_url(info.port) if (kind=="api" and info.port) else None
    return {
        "status":"ok","name":body.name,"kind":kind,"pid":info.pid,"url":url,
        "restart_policy": pol.model_dump()
    }

@app.post("/users/{uid}/skills/{name}/secrets")
def rotate_secrets(uid:str, name:str, payload: Dict[str,str]):
    uid, name = slug(uid), slug(name)
    set_skill_secrets(uid, name, payload or {})

    if PROCS.get((uid,name)):
        stop_proc(uid, name, manual=True)
        spec = SPECS.get((uid,name))
        wdir = spec.wdir if spec else workspace(uid, name)
        kind = spec.kind if spec else ("api" if detect_api_from_code((wdir/"main.py").read_text(encoding="utf-8", errors="ignore")) else "worker")
        port = find_free_port() if kind=="api" else None
        pol  = spec.policy if spec else RestartPolicy()
        start_proc(uid, name, kind, wdir, port, pol)

    return {"rotated": True}

@app.get("/users/{uid}/skills/{name}")
def status(uid:str, name:str):
    uid, name = slug(uid), slug(name)
    key = (uid,name)
    info = PROCS.get(key)
    if not info:
        return {"name": name, "status": "stopped", "url": None, "restarts": 0}
    url = skill_public_url(info.port) if (info.kind=="api" and info.port) else None
    return {
        "name": name, "status": "running", "kind": info.kind, "url": url,
        "pid": info.pid, "restarts": info.restarts, "policy": info.policy.model_dump()
    }

@app.post("/users/{uid}/skills/{name}/stop")
def stop(uid:str, name:str):
    uid, name = slug(uid), slug(name)
    stop_proc(uid, name, manual=True)
    return {"stopped": name}

@app.post("/users/{uid}/skills/{name}/start")
def start(uid:str, name:str):
    uid, name = slug(uid), slug(name)
    key = (uid, name)
    if PROCS.get(key):
        stop_proc(uid, name, manual=True)

    wdir = workspace(uid, name)
    if not (wdir/"main.py").exists():
        raise HTTPException(404, "Skill não encontrada")

    kind = "api" if detect_api_from_code((wdir/"main.py").read_text(encoding="utf-8", errors="ignore")) else "worker"
    port = find_free_port() if kind=="api" else None
    pol = SPECS.get(key).policy if SPECS.get(key) else RestartPolicy()
    info = start_proc(uid, name, kind, wdir, port, pol)
    url = skill_public_url(info.port) if (kind=="api" and info.port) else None
    return {"started": name, "url": url, "restarts": info.restarts}

@app.post("/users/{uid}/skills/{name}/restart")
def restart(uid:str, name:str):
    uid, name = slug(uid), slug(name)
    wdir = workspace(uid, name)
    if not (wdir/"main.py").exists():
        raise HTTPException(404, "Skill não encontrada")
    stop_proc(uid, name, manual=True)
    spec = SPECS.get((uid,name))
    kind = spec.kind if spec else ("api" if detect_api_from_code((wdir/"main.py").read_text(encoding="utf-8", errors="ignore")) else "worker")
    port = find_free_port() if kind=="api" else None
    pol = spec.policy if spec else RestartPolicy()
    info = start_proc(uid, name, kind, wdir, port, pol)
    url = skill_public_url(info.port) if (kind=="api" and info.port) else None
    return {"restarted": name, "url": url, "restarts": info.restarts}

@app.delete("/users/{uid}/skills/{name}")
def delete(uid:str, name:str):
    uid, name = slug(uid), slug(name)
    key = (uid, name)
    DELETING.add(key)
    try:
        stop_proc(uid, name, manual=True)

        try:
            _secret_path(uid, name).unlink()
        except Exception:
            pass

        wdir = workspace(uid, name)
        _force_rmtree(wdir)

        user_dir = BASE / uid
        try:
            if user_dir.exists() and not any(user_dir.iterdir()):
                user_dir.rmdir()
        except Exception:
            pass

        SPECS.pop(key, None)
        RESTART_HISTORY.pop(key, None)
        BACKOFF_NEXT_TS.pop(key, None)
        QUARANTINE_UNTIL.pop(key, None)
        MANUAL_STOP.discard(key)

        residual = (wdir.exists() or (_secret_path(uid, name).exists()))
        return {"deleted": name, "residual": residual}
    finally:
        DELETING.discard(key)

def _logfile(uid:str, name:str, which:str)->Path:
    wdir = workspace(uid, name) / "_logs"
    return (wdir/"stdout.log") if which=="stdout" else (wdir/"stderr.log")

@app.get("/users/{uid}/skills/{name}/logs")
def logs(uid:str, name:str, which:str="stdout", lines:int=200):
    uid, name = slug(uid), slug(name)
    path = _logfile(uid, name, which)
    if not path.exists():
        return PlainTextResponse("", media_type="text/plain")
    content = path.read_text(encoding="utf-8", errors="ignore").splitlines(True)
    tail = content[-lines:] if lines>0 else content
    return PlainTextResponse("".join(tail), media_type="text/plain")

@app.get("/users/{uid}/skills/{name}/logs/stream")
async def logs_stream(uid:str, name:str, which:str="stdout"):
    uid, name = slug(uid), slug(name)
    path = _logfile(uid, name, which)
    if not path.exists():
        return StreamingResponse(iter([b""]), media_type="text/event-stream")
    async def gen():
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if line:
                    yield f"data: {line.rstrip()}\n\n"
                else:
                    await asyncio.sleep(0.4)
    return StreamingResponse(gen(), media_type="text/event-stream")

# ========================== Export / Import endpoints ====================== #

@app.get("/users/{uid}/skills/{name}/export")
def export_skill(uid: str, name: str):
    manifest = build_manifest(uid, name)
    filename = f"{slug(name)}.skill.json"
    return JSONResponse(
        content=manifest,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@app.post("/users/{uid}/skills/import")
def import_skill(uid: str, body: ImportIn):
    uid_s = slug(uid)

    m = body.manifest or {}
    schema = m.get("schema")
    if schema != EXPORT_SCHEMA:
        raise HTTPException(400, f"schema inválido; esperado {EXPORT_SCHEMA!r}")

    src_name = m.get("name")
    if not src_name:
        raise HTTPException(400, "manifest.name ausente")

    name = slug(body.name or src_name)
    wdir = workspace(uid_s, name)

    if wdir.exists() and not body.overwrite:
        raise HTTPException(409, f"Skill '{name}' já existe (use overwrite=true).")

    code = m.get("code", "")
    requirements = m.get("requirements", "")
    kind = m.get("kind") or ("api" if detect_api_from_code(code) else "worker")

    pol = _merge_restart_policy_from_dict(RestartPolicy(), m.get("restart_policy"))

    if PROCS.get((uid_s, name)):
        stop_proc(uid_s, name, manual=True)
    if wdir.exists() and body.overwrite:
        _force_rmtree(wdir)

    new_wdir = write_files(uid_s, name, code, requirements)

    if body.secrets:
        set_skill_secrets(uid_s, name, body.secrets)

    url = None
    if body.start:
        port = find_free_port() if kind == "api" else None
        info = start_proc(uid_s, name, kind, new_wdir, port, pol)
        url = skill_public_url(info.port) if (kind == "api" and info.port) else None

    return {
        "imported": name,
        "started": bool(body.start),
        "url": url,
        "kind": kind,
        "restart_policy": pol.model_dump(),
        "secret_keys_expected": m.get("secret_keys", []),
    }

# ============================== Main (opcional) =========================== #
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=CFG.agent.bind_host, port=CFG.agent.port)
