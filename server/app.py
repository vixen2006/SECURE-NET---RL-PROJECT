import os
import sys
from typing import Any, Dict, List

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _parent not in sys.path:
    sys.path.insert(0, _parent)

try:
    from securenet_env.models import SecureNetAction, SecureNetReward, StepResult
    from securenet_env.server.securenet_environment import SCENARIOS, SecureNetEnvironment
except ImportError:
    from models import SecureNetAction, SecureNetReward, StepResult
    from server.securenet_environment import SCENARIOS, SecureNetEnvironment


app = FastAPI(
    title="SecureNet OpenEnv Benchmark",
    version="3.0.0",
    description="Real-world SOC incident triage environment with deterministic task graders.",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

env = SecureNetEnvironment()

# ── In-memory training telemetry ────────────────────────────────────────────
_episode_rewards: List[float] = []
_episode_scores: List[float] = []
_episode_log_store: List[Dict[str, Any]] = []  # actions for the current episode
_episode_number: int = 0
_current_difficulty: str = "easy"

# Static IOC threat-intel database (used by dashboard feed)
THREAT_INTEL_DB: Dict[str, Dict[str, str]] = {
    "185.220.101.45": {"actor": "APT-Phish-23", "mitre": "T1566.001", "threat": "CRITICAL"},
    "172.16.0.200":   {"actor": "LockBit 3.0",  "mitre": "T1486",     "threat": "CRITICAL"},
    "91.92.109.200":  {"actor": "FIN7",          "mitre": "T1071.001", "threat": "HIGH"},
    "193.56.29.11":   {"actor": "NOBELIUM",      "mitre": "T1190",     "threat": "CRITICAL"},
    "45.142.212.100": {"actor": "Scattered Spider","mitre":"T1657",    "threat": "HIGH"},
    "10.10.50.99":    {"actor": "RaaS Affiliate", "mitre": "T1021.002","threat": "HIGH"},
    "198.51.100.77":  {"actor": "Kimsuky",        "mitre": "T1059.001","threat": "MEDIUM"},
    "203.0.113.45":   {"actor": "APT41",          "mitre": "T1218.011","threat": "HIGH"},
    "8.8.4.200":      {"actor": "PlugX Loader",   "mitre": "T1105",    "threat": "MEDIUM"},
    "45.33.99.120":   {"actor": "DarkSide",       "mitre": "T1490",    "threat": "CRITICAL"},
}

# Node type mapping for the topology canvas
NODE_TYPE_MAP: Dict[str, str] = {
    "Helpdesk-PC":  "endpoint",
    "File-Server":  "server",
    "Finance-Laptop": "endpoint",
    "Mail-Relay":   "server",
    "Payroll-DB":   "database",
    "Build-Server": "server",
    "Backup-Node":  "server",
    "Payments-API": "server",
    "SOC-Jumpbox":  "network",
}

# Topology edges (full mesh by adjacency group)
TOPOLOGY_MAP: Dict[str, Dict[str, List[str]]] = {
    "easy": {
        "Helpdesk-PC": ["File-Server"],
        "File-Server": ["Helpdesk-PC"],
    },
    "medium": {
        "Finance-Laptop": ["Mail-Relay", "Payroll-DB"],
        "Mail-Relay":     ["Finance-Laptop", "Payroll-DB"],
        "Payroll-DB":     ["Finance-Laptop", "Mail-Relay"],
    },
    "hard": {
        "Build-Server": ["Backup-Node", "SOC-Jumpbox", "Payments-API"],
        "Backup-Node":  ["Build-Server", "Payments-API"],
        "Payments-API": ["Build-Server", "Backup-Node", "SOC-Jumpbox"],
        "SOC-Jumpbox":  ["Build-Server", "Payments-API"],
    },
}


# ── Serve dashboard ──────────────────────────────────────────────────────────
_dashboard_dir = os.path.join(_parent, "dashboard")

@app.get("/", include_in_schema=False)
def dashboard_root() -> FileResponse:
    return FileResponse(os.path.join(_dashboard_dir, "index.html"))

# Mount /dashboard path too for direct access
@app.get("/dashboard", include_in_schema=False)
def dashboard_alias() -> FileResponse:
    return FileResponse(os.path.join(_dashboard_dir, "index.html"))


# ── Core benchmark endpoints ─────────────────────────────────────────────────

@app.post("/reset")
def reset_env(task: str = Query("easy", description="easy|medium|hard")) -> Dict[str, Any]:
    global _episode_number, _current_difficulty, _episode_log_store
    _episode_number += 1
    _current_difficulty = task if task in SCENARIOS else "easy"
    _episode_log_store = []
    observation = env.reset(task)
    return StepResult(
        observation=observation,
        reward=SecureNetReward(value=0.0, partial_score=0.0, step_reward=0.0, reason="reset"),
        done=False,
        info={"task": SCENARIOS[env.current_task]["id"], "difficulty": env.current_task},
    ).model_dump()


@app.post("/step")
def step_env(action: SecureNetAction) -> Dict[str, Any]:
    result = env.step(action)
    # Record to episode log for dashboard
    _episode_log_store.append({
        "step": result["observation"]["step_index"],
        "action_type": action.action_type.value,
        "target_node": action.target_node or "",
        "ip_address":  action.ip_address or "",
        "ioc":         action.ioc or "",
        "process_name": action.process_name or "",
        "reward": result["reward"]["step_reward"],
        "success": result["observation"]["success"],
    })
    # If episode done, record the score
    if result["done"]:
        _episode_rewards.append(result["reward"]["value"])
        _episode_scores.append(result["reward"]["partial_score"])
    return result


@app.get("/state")
def get_state() -> Dict[str, Any]:
    base = env.state()
    task = env.current_task
    scenario = SCENARIOS.get(task, SCENARIOS["easy"])
    # Build enriched network for the canvas
    network: Dict[str, Any] = {}
    for name, node in env.network.items():
        real_status = node.get("status", "unknown")
        if name in env.isolated_hosts:
            real_status = "isolated"
        network[name] = {
            "critical": node["critical"],
            "status": real_status,
            "node_type": NODE_TYPE_MAP.get(name, "endpoint"),
        }
    base["network"] = network
    base["topology"] = TOPOLOGY_MAP.get(task, {})
    base["compromised"] = list(env.compromised)
    base["isolated"] = list(env.isolated_hosts)
    kill_stages = ["Reconnaissance", "Initial Access", "Persistence", "Lateral Movement", "Exfiltration"]
    kc_idx = min(env.step_count // max(1, env.max_steps // len(kill_stages)), len(kill_stages) - 1)
    base["kill_chain_idx"] = kc_idx
    base["kill_chain"] = kill_stages[kc_idx]
    return base


@app.get("/tasks")
def tasks() -> Dict[str, Any]:
    rows = []
    for diff in ["easy", "medium", "hard"]:
        scenario = SCENARIOS[diff]
        rows.append(
            {
                "id": scenario["id"],
                "difficulty": diff,
                "description": scenario["description"],
                "max_steps": scenario["max_steps"],
                "reward_range": [0.0, 1.0],
            }
        )
    return {"tasks": rows}


@app.get("/grade")
def grade(task: str = Query(..., description="soc_triage_easy|soc_triage_medium|soc_triage_hard")) -> Dict[str, Any]:
    try:
        score = env.grade_task(task)
    except ValueError as exc:
        return {"error": str(exc)}
    return {"task": task, "score": score, "score_range": [0.0, 1.0]}


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "service": "securenet-openenv", "version": "3.0.0"}


# ── Dashboard telemetry endpoints ────────────────────────────────────────────

@app.get("/stats")
def get_stats() -> Dict[str, Any]:
    """Training statistics polled by the dashboard."""
    return {
        "rewards": list(_episode_rewards),
        "scores": list(_episode_scores),
        "difficulty": _current_difficulty,
        "episode_count": _episode_number,
    }


@app.get("/episode_log")
def get_episode_log() -> Dict[str, Any]:
    """Current episode action log polled by the dashboard."""
    return {
        "episode": _episode_number,
        "log": list(_episode_log_store),
    }


@app.get("/threat_intel_db")
def get_threat_intel_db() -> Dict[str, Any]:
    """Static IOC threat-intel database for the dashboard feed."""
    return THREAT_INTEL_DB


def main() -> None:
    import uvicorn

    port = int(os.getenv("PORT", "7860"))
    uvicorn.run("server.app:app", host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
