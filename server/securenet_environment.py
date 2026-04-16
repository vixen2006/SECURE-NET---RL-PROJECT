import copy
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:
    from securenet_env.models import SecureNetAction, SecureNetObservation, SecureNetReward, StepResult
except ImportError:
    from models import SecureNetAction, SecureNetObservation, SecureNetReward, StepResult


SUSPICIOUS_MARKERS = [
    "malicious",
    "mimikatz",
    "lockbit",
    "webshell",
    "keylogger",
    "backdoor",
    "powershell -enc",
    "beacon",
    "exfil",
]


SCENARIOS: Dict[str, Dict[str, Any]] = {
    "easy": {
        "id": "soc_triage_easy",
        "description": "Single-host phishing compromise triage.",
        "max_steps": 12,
        "nodes": {
            "Helpdesk-PC": {
                "critical": False,
                "status": "infected",
                "processes": ["outlook.exe", "powershell -enc (malicious)", "chrome.exe"],
                "logs": "User clicked phishing link. Encoded PowerShell launched and beaconed to 185.220.101.45.",
            },
            "File-Server": {
                "critical": True,
                "status": "healthy",
                "processes": ["smbd", "backupd"],
                "logs": "Normal file share traffic and scheduled backup jobs.",
            },
        },
        "compromised": ["Helpdesk-PC"],
        "attacker_iocs": ["185.220.101.45"],
        "drift": {},
    },
    "medium": {
        "id": "soc_triage_medium",
        "description": "Two-host compromise with credential theft and C2.",
        "max_steps": 16,
        "nodes": {
            "Finance-Laptop": {
                "critical": False,
                "status": "infected",
                "processes": ["excel.exe", "keylogger.dll (malicious)", "teams.exe"],
                "logs": "Credential capture detected; periodic exfil to 172.16.0.200.",
            },
            "Mail-Relay": {
                "critical": False,
                "status": "infected",
                "processes": ["sendmail", "webshell.php (malicious)"],
                "logs": "Outbound phishing campaign with suspicious shell activity.",
            },
            "Payroll-DB": {
                "critical": True,
                "status": "healthy",
                "processes": ["postgres", "pgagent"],
                "logs": "No suspicious activity, stable query volume.",
            },
        },
        "compromised": ["Finance-Laptop", "Mail-Relay"],
        "attacker_iocs": ["172.16.0.200", "91.92.109.200"],
        "drift": {},
    },
    "hard": {
        "id": "soc_triage_hard",
        "description": "Ransomware spread prevention with adversarial drift.",
        "max_steps": 20,
        "nodes": {
            "Build-Server": {
                "critical": False,
                "status": "infected",
                "processes": ["jenkins", "lockbit3.exe (malicious)", "psexec.exe"],
                "logs": "Ransomware binary executed; lateral movement attempt in progress.",
            },
            "Backup-Node": {
                "critical": False,
                "status": "infected",
                "processes": ["veeam-agent", "svc_update (malicious)"],
                "logs": "Backup catalog tampered and exfil channel opened.",
            },
            "Payments-API": {
                "critical": True,
                "status": "healthy",
                "processes": ["gunicorn", "nginx"],
                "logs": "Production payment traffic normal. Latency within SLA.",
            },
            "SOC-Jumpbox": {
                "critical": False,
                "status": "healthy",
                "processes": ["ssh", "falco"],
                "logs": "Routine admin operations.",
            },
        },
        "compromised": ["Build-Server", "Backup-Node"],
        "attacker_iocs": ["193.56.29.11", "45.142.212.100"],
        "drift": {5: ("Build-Server", "SOC-Jumpbox")},
    },
}


@dataclass
class EpisodeStats:
    queried_infected: int = 0
    analyzed_hits: int = 0
    blocked_iocs: int = 0
    quarantined_hits: int = 0
    isolated_infected: int = 0
    false_positives: int = 0


class SecureNetEnvironment:
    def __init__(self) -> None:
        self.current_task = "easy"
        self.network: Dict[str, Dict[str, Any]] = {}
        self._template: Dict[str, Any] = {}
        self.step_count = 0
        self.max_steps = 0
        self.done = False
        self.compromised: List[str] = []
        self.initial_compromised: List[str] = []
        self.blocked_iocs: List[str] = []
        self.isolated_hosts: List[str] = []
        self.quarantined: Dict[str, str] = {}
        self.queried_nodes: List[str] = []
        self.analyzed_nodes: List[str] = []
        self.episode_return = 0.0
        self.last_score_by_task: Dict[str, float] = {}
        self.last_action_fingerprint = ""
        self.repetition_count = 0
        self.stats = EpisodeStats()
        self.reset("easy")

    def reset(self, task: str = "easy") -> SecureNetObservation:
        if task not in SCENARIOS:
            task = "easy"

        self.current_task = task
        self._template = SCENARIOS[task]
        self.network = copy.deepcopy(self._template["nodes"])
        self.compromised = list(self._template["compromised"])
        self.initial_compromised = list(self._template["compromised"])
        self.step_count = 0
        self.max_steps = self._template["max_steps"]
        self.done = False
        self.blocked_iocs = []
        self.isolated_hosts = []
        self.quarantined = {}
        self.queried_nodes = []
        self.analyzed_nodes = []
        self.episode_return = 0.0
        self.last_action_fingerprint = ""
        self.repetition_count = 0
        self.stats = EpisodeStats()

        return self._observation(
            result=(
                f"Task {self._template['id']} reset. "
                f"Investigate {len(self.network)} hosts and contain threats."
            ),
            success=True,
            echoed_message=f"{self._template['id']} initialized",
        )

    def state(self) -> Dict[str, Any]:
        visible = {}
        for name, node in self.network.items():
            visible[name] = {
                "critical": node["critical"],
                "status": "isolated" if name in self.isolated_hosts else "unknown",
                "processes": list(node["processes"]),
            }

        return {
            "task": self._template.get("id", "soc_triage_easy"),
            "difficulty": self.current_task,
            "step": self.step_count,
            "max_steps": self.max_steps,
            "done": self.done,
            "blocked_iocs": list(self.blocked_iocs),
            "isolated_hosts": list(self.isolated_hosts),
            "visible_network": visible,
        }

    def step(self, action: SecureNetAction) -> Dict[str, Any]:
        if self.done:
            return StepResult(
                observation=SecureNetObservation(
                    result="Episode already finished. Call reset().",
                    success=False,
                    echoed_message="episode_done",
                    available_nodes=list(self.network.keys()),
                    blocked_iocs=list(self.blocked_iocs),
                    isolated_hosts=list(self.isolated_hosts),
                    step_index=self.step_count,
                    max_steps=self.max_steps,
                ),
                reward=SecureNetReward(
                    value=self.last_score_by_task.get(self._template["id"], 0.0),
                    partial_score=max(0.0, min(1.0, self._partial_score())),
                    step_reward=0.0,
                    reason="no_op_after_done",
                ),
                done=True,
                info=self._episode_info(final=True),
            ).model_dump()

        self.step_count += 1
        step_reward = -0.02
        reasons: List[str] = ["step_cost"]

        fingerprint = f"{action.action_type.value}|{action.target_node}|{action.ip_address}|{action.ioc}|{action.process_name}"
        if fingerprint == self.last_action_fingerprint:
            self.repetition_count += 1
        else:
            self.repetition_count = 0
        self.last_action_fingerprint = fingerprint

        if self.repetition_count >= 2:
            step_reward -= 0.05
            reasons.append("loop_penalty")

        drift_message = self._apply_drift_if_needed()

        try:
            result, delta, op_reasons = self._dispatch(action)
            step_reward += delta
            reasons.extend(op_reasons)
            success = True
            error = ""
        except ValueError as exc:
            result = "Invalid action parameters."
            step_reward -= 0.10
            reasons.append("invalid_action")
            success = False
            error = str(exc)

        self.episode_return += step_reward

        terminated = False
        if not self.compromised:
            terminated = True
            reasons.append("all_threats_contained")

        if self.step_count >= self.max_steps:
            terminated = True
            reasons.append("max_steps_reached")

        self.done = terminated
        final_score = self._grade_current_episode() if terminated else 0.0

        if terminated:
            self.last_score_by_task[self._template["id"]] = final_score

        message = result if not drift_message else f"{result}\n{drift_message}"

        obs = self._observation(result=message, success=success, echoed_message=";".join(reasons))

        reward = SecureNetReward(
            value=final_score if terminated else 0.0,
            partial_score=max(0.0, min(1.0, self._partial_score())),
            step_reward=max(-1.0, min(1.0, step_reward)),
            reason="|".join(reasons),
        )

        info = self._episode_info(final=terminated)
        if error:
            info["error"] = error

        return StepResult(observation=obs, reward=reward, done=terminated, info=info).model_dump()

    def grade_task(self, task_id: str) -> float:
        mapped = {
            "soc_triage_easy": "soc_triage_easy",
            "soc_triage_medium": "soc_triage_medium",
            "soc_triage_hard": "soc_triage_hard",
            "easy": "soc_triage_easy",
            "medium": "soc_triage_medium",
            "hard": "soc_triage_hard",
        }
        canonical = mapped.get(task_id)
        if not canonical:
            raise ValueError("Unknown task id")
        return float(self.last_score_by_task.get(canonical, 0.0))

    def _dispatch(self, action: SecureNetAction) -> Tuple[str, float, List[str]]:
        action_type = action.action_type.value
        if action_type == "query_logs":
            return self._query_logs(action.target_node)
        if action_type == "analyze_process":
            return self._analyze_process(action.target_node)
        if action_type == "block_ip":
            return self._block_ioc(action.ip_address)
        if action_type == "threat_intel":
            return self._block_ioc(action.ioc or action.ip_address)
        if action_type == "quarantine_process":
            return self._quarantine(action.target_node, action.process_name)
        if action_type == "isolate_host":
            return self._isolate(action.target_node)
        raise ValueError(f"Unsupported action_type '{action_type}'")

    def _query_logs(self, node: Optional[str]) -> Tuple[str, float, List[str]]:
        if not node or node not in self.network:
            raise ValueError("target_node is required for query_logs")

        bonus = 0.08
        reasons = ["query_logs"]
        if node in self.queried_nodes:
            bonus -= 0.04
            reasons.append("repeat_query")
        else:
            self.queried_nodes.append(node)
            if node in self.initial_compromised:
                bonus += 0.20
                self.stats.queried_infected += 1
                reasons.append("found_infected_logs")

        return f"Logs from {node}: {self.network[node]['logs']}", bonus, reasons

    def _analyze_process(self, node: Optional[str]) -> Tuple[str, float, List[str]]:
        if not node or node not in self.network:
            raise ValueError("target_node is required for analyze_process")

        processes = self.network[node]["processes"]
        suspicious = [p for p in processes if any(marker in p.lower() for marker in SUSPICIOUS_MARKERS)]
        reasons = ["analyze_process"]
        if suspicious:
            self.stats.analyzed_hits += 1
            return (
                f"Suspicious processes on {node}: {', '.join(suspicious)}",
                0.22,
                reasons + ["malicious_process_detected"],
            )
        return f"No suspicious process found on {node}.", -0.03, reasons + ["clean_host_analysis"]

    def _block_ioc(self, ioc: Optional[str]) -> Tuple[str, float, List[str]]:
        if not ioc:
            raise ValueError("ip_address or ioc is required")

        reasons = ["block_ioc"]
        if ioc in self.blocked_iocs:
            return f"IOC {ioc} already blocked.", -0.03, reasons + ["repeat_block"]

        self.blocked_iocs.append(ioc)
        if ioc in self._template["attacker_iocs"]:
            self.stats.blocked_iocs += 1
            return f"IOC {ioc} blocked successfully.", 0.16, reasons + ["known_attacker_blocked"]
        return f"IOC {ioc} blocked (not part of known attacker set).", -0.01, reasons + ["unknown_ioc"]

    def _quarantine(self, node: Optional[str], process_name: Optional[str]) -> Tuple[str, float, List[str]]:
        if not node or node not in self.network:
            raise ValueError("target_node is required for quarantine_process")
        if not process_name:
            raise ValueError("process_name is required for quarantine_process")

        processes = self.network[node]["processes"]
        reasons = ["quarantine_process"]
        for proc in list(processes):
            if process_name.lower() in proc.lower() and any(marker in proc.lower() for marker in SUSPICIOUS_MARKERS):
                processes.remove(proc)
                self.quarantined[node] = proc
                self.stats.quarantined_hits += 1
                return f"Quarantined process '{proc}' on {node}.", 0.18, reasons + ["quarantine_hit"]

        return f"Process '{process_name}' not quarantined on {node}.", -0.06, reasons + ["quarantine_miss"]

    def _isolate(self, node: Optional[str]) -> Tuple[str, float, List[str]]:
        if not node or node not in self.network:
            raise ValueError("target_node is required for isolate_host")

        reasons = ["isolate_host"]
        if node in self.isolated_hosts:
            return f"{node} already isolated.", -0.02, reasons + ["repeat_isolation"]

        self.isolated_hosts.append(node)
        self.network[node]["status"] = "isolated"

        if node in self.compromised:
            self.compromised.remove(node)
            self.stats.isolated_infected += 1
            return f"{node} isolated. Threat contained.", 0.50, reasons + ["isolated_infected"]

        self.stats.false_positives += 1
        penalty = 0.30 if self.network[node]["critical"] else 0.22
        return f"False positive isolation on {node}. Service disruption introduced.", -penalty, reasons + ["isolated_healthy"]

    def _apply_drift_if_needed(self) -> str:
        rule = self._template.get("drift", {}).get(self.step_count)
        if not rule:
            return ""

        source, target = rule
        if source in self.compromised and target not in self.compromised and target not in self.isolated_hosts:
            self.compromised.append(target)
            self.network[target]["status"] = "infected"
            self.network[target]["logs"] = f"Adversarial drift from {source}. New lateral compromise detected on {target}."
            return f"[DRIFT] {target} became compromised due to lateral movement from {source}."
        return ""

    def _partial_score(self) -> float:
        total_comp = max(1, len(self.initial_compromised))
        containment_progress = self.stats.isolated_infected / total_comp
        intel_progress = self.stats.blocked_iocs / max(1, len(self._template["attacker_iocs"]))
        query_progress = self.stats.queried_infected / total_comp
        score = 0.5 * containment_progress + 0.3 * intel_progress + 0.2 * query_progress
        return max(0.0, min(1.0, score))

    def _grade_current_episode(self) -> float:
        total_comp = max(1, len(self.initial_compromised))
        healthy_hosts = max(1, len(self.network) - len(self.initial_compromised))

        containment = self.stats.isolated_infected / total_comp
        intel = self.stats.blocked_iocs / max(1, len(self._template["attacker_iocs"]))
        investigation = self.stats.queried_infected / total_comp
        precision = 1.0 - (self.stats.false_positives / healthy_hosts)
        precision = max(0.0, min(1.0, precision))

        weighted = 0.45 * containment + 0.20 * intel + 0.20 * precision + 0.15 * investigation
        return max(0.0, min(1.0, round(weighted, 4)))

    def _episode_info(self, final: bool) -> Dict[str, Any]:
        return {
            "task": self._template.get("id", "soc_triage_easy"),
            "difficulty": self.current_task,
            "step": self.step_count,
            "max_steps": self.max_steps,
            "remaining_compromised": list(self.compromised),
            "blocked_iocs": list(self.blocked_iocs),
            "isolated_hosts": list(self.isolated_hosts),
            "final": final,
        }

    def _observation(self, result: str, success: bool, echoed_message: str) -> SecureNetObservation:
        return SecureNetObservation(
            result=result,
            success=success,
            echoed_message=echoed_message,
            available_nodes=list(self.network.keys()),
            blocked_iocs=list(self.blocked_iocs),
            isolated_hosts=list(self.isolated_hosts),
            step_index=self.step_count,
            max_steps=self.max_steps,
        )
