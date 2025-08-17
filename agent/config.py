# config/config.py
from __future__ import annotations
import os, sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

try:
    import tomllib  # py3.11+
except Exception:
    tomllib = None

@dataclass
class AgentCfg:
    bind_host: str = "127.0.0.1"
    port: int = 8081
    base_dir: str = "./userdata"
    secrets_dir: str = "./userdata/_secrets"
    public_base_url: str = ""
    log_level: str = "INFO"
    json_logs: bool = True
    cors_allow_origins: List[str] = field(default_factory=list)

@dataclass
class SkillsCfg:
    api_port_start: int = 18000
    api_port_end: int = 19999

@dataclass
class RestartDefaultsCfg:
    mode: str = "on-failure"
    max_restarts: int = 5
    window_seconds: int = 60
    min_uptime: float = 3.0
    backoff_seconds: float = 1.0
    backoff_factor: float = 1.5
    backoff_max: float = 30.0

@dataclass
class ObservabilityCfg:
    prometheus_metrics: bool = True
    log_rotate_max_bytes: int = 5 * 1024 * 1024
    log_rotate_backups: int = 2

@dataclass
class SecurityCfg:
    secrets_master: Optional[bytes] = None
    secrets_master_file: Optional[str] = None
    allow_plaintext_env: bool = False

@dataclass
class Config:
    agent: AgentCfg = field(default_factory=AgentCfg)
    skills: SkillsCfg = field(default_factory=SkillsCfg)
    restart_defaults: RestartDefaultsCfg = field(default_factory=RestartDefaultsCfg)
    observability: ObservabilityCfg = field(default_factory=ObservabilityCfg)
    security: SecurityCfg = field(default_factory=SecurityCfg)

def _deep_update(dc: dict, upd: dict):
    for k, v in (upd or {}).items():
        if isinstance(v, dict) and isinstance(dc.get(k), dict):
            _deep_update(dc[k], v)
        else:
            dc[k] = v

def _load_toml(path: Path) -> dict:
    if not tomllib:
        return {}
    if not path.exists():
        return {}
    with path.open("rb") as f:
        return tomllib.load(f) or {}

def _env_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.lower() in ("1","true","yes","on")

def load_config() -> Config:
    data: dict = {}
    cfg_file = os.getenv("AGENT_CONFIG", "config/agent.toml")
    data_file = _load_toml(Path(cfg_file))
    _deep_update(data, data_file)

    agent = data.setdefault("agent", {})
    agent["bind_host"]  = os.getenv("AGENT_BIND_HOST",  agent.get("bind_host",  "127.0.0.1"))
    agent["port"]       = int(os.getenv("AGENT_PORT",   agent.get("port", 8081)))
    agent["base_dir"]   = os.getenv("AGENT_BASE_DIR",   agent.get("base_dir", "./userdata"))
    agent["secrets_dir"]= os.getenv("AGENT_SECRETS_DIR",agent.get("secrets_dir","./userdata/_secrets"))
    agent["public_base_url"] = os.getenv("AGENT_PUBLIC_BASE_URL", agent.get("public_base_url", ""))
    agent["log_level"]  = os.getenv("AGENT_LOG_LEVEL", agent.get("log_level", "INFO"))
    agent["json_logs"]  = _env_bool("AGENT_JSON_LOGS", agent.get("json_logs", True))
    cors_env = os.getenv("AGENT_CORS_ALLOW_ORIGINS", "")
    if cors_env:
        agent["cors_allow_origins"] = [x.strip() for x in cors_env.split(",") if x.strip()]

    skills = data.setdefault("skills", {})
    skills["api_port_start"] = int(os.getenv("AGENT_API_PORT_START", skills.get("api_port_start", 18000)))
    skills["api_port_end"]   = int(os.getenv("AGENT_API_PORT_END",   skills.get("api_port_end",   19999)))

    rd = data.setdefault("restart_defaults", {})
    rd["mode"]             = os.getenv("AGENT_RESTART_MODE", rd.get("mode","on-failure"))
    rd["max_restarts"]     = int(os.getenv("AGENT_RESTART_MAX", rd.get("max_restarts",5)))
    rd["window_seconds"]   = int(os.getenv("AGENT_RESTART_WINDOW", rd.get("window_seconds",60)))
    rd["min_uptime"]       = float(os.getenv("AGENT_RESTART_MIN_UPTIME", rd.get("min_uptime",3.0)))
    rd["backoff_seconds"]  = float(os.getenv("AGENT_BACKOFF_SECONDS", rd.get("backoff_seconds",1.0)))
    rd["backoff_factor"]   = float(os.getenv("AGENT_BACKOFF_FACTOR", rd.get("backoff_factor",1.5)))
    rd["backoff_max"]      = float(os.getenv("AGENT_BACKOFF_MAX", rd.get("backoff_max",30.0)))

    ob = data.setdefault("observability", {})
    ob["prometheus_metrics"]   = _env_bool("AGENT_PROM_METRICS", ob.get("prometheus_metrics", True))
    ob["log_rotate_max_bytes"] = int(os.getenv("AGENT_LOG_ROTATE_MAX_BYTES", ob.get("log_rotate_max_bytes", 5*1024*1024)))
    ob["log_rotate_backups"]   = int(os.getenv("AGENT_LOG_ROTATE_BACKUPS", ob.get("log_rotate_backups", 2)))

    sec = data.setdefault("security", {})
    env_master = os.getenv("AGENT_SECRETS_MASTER", "")
    env_master_file = os.getenv("AGENT_SECRETS_MASTER_FILE", "")
    if env_master:
        sec["secrets_master"] = env_master
    if env_master_file:
        sec["secrets_master_file"] = env_master_file
    sec["allow_plaintext_env"] = _env_bool("AGENT_ALLOW_PLAINTEXT_ENV", sec.get("allow_plaintext_env", False))

    cfg = Config(
        agent = AgentCfg(**agent),
        skills = SkillsCfg(**skills),
        restart_defaults = RestartDefaultsCfg(**rd),
        observability = ObservabilityCfg(**ob),
        security = SecurityCfg(
            secrets_master = None,
            secrets_master_file = sec.get("secrets_master_file"),
            allow_plaintext_env = sec.get("allow_plaintext_env", False),
        )
    )

    master_text = env_master or sec.get("secrets_master") or ""
    if not master_text and cfg.security.secrets_master_file:
        try:
            master_text = Path(cfg.security.secrets_master_file).read_text(encoding="utf-8").strip()
        except Exception:
            master_text = ""
    if master_text:
        try:
            cfg.security.secrets_master = master_text.encode("utf-8")
        except Exception:
            cfg.security.secrets_master = None

    return cfg

CFG = load_config()
