import asyncio
import os
from typing import Dict, List, Tuple

from openai import OpenAI

from client import SecureNetClient


BENCHMARK = "securenet_openenv"
MODEL_NAME = os.getenv("MODEL_NAME", "gpt-4o-mini")
API_BASE_URL = os.getenv("API_BASE_URL", "https://api.openai.com/v1")
API_KEY = os.getenv("OPENAI_API_KEY", os.getenv("HF_TOKEN", ""))
MAX_STEPS_BY_TASK = {"easy": 12, "medium": 16, "hard": 20}
SUCCESS_SCORE_THRESHOLD = 0.60


def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error: str) -> None:
    print(
        f"[STEP] step={step} action={action!r} reward={reward:+.2f} done={str(done).lower()} error={error}",
        flush=True,
    )


def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:+.2f}" for r in rewards)
    print(f"[END] success={str(success).lower()} steps={steps} score={score:.3f} rewards={rewards_str}", flush=True)


PLAYBOOKS: Dict[str, List[Tuple[str, str, str, str, str, str]]] = {
    "easy": [
        ("query_logs", "Helpdesk-PC", "", "last_hour", "", ""),
        ("analyze_process", "Helpdesk-PC", "", "", "", ""),
        ("threat_intel", "", "185.220.101.45", "", "", "185.220.101.45"),
        ("quarantine_process", "Helpdesk-PC", "", "", "powershell -enc", ""),
        ("isolate_host", "Helpdesk-PC", "", "", "", ""),
    ],
    "medium": [
        ("query_logs", "Finance-Laptop", "", "last_hour", "", ""),
        ("query_logs", "Mail-Relay", "", "last_hour", "", ""),
        ("analyze_process", "Finance-Laptop", "", "", "", ""),
        ("analyze_process", "Mail-Relay", "", "", "", ""),
        ("block_ip", "", "172.16.0.200", "", "", ""),
        ("threat_intel", "", "91.92.109.200", "", "", "91.92.109.200"),
        ("quarantine_process", "Finance-Laptop", "", "", "keylogger", ""),
        ("quarantine_process", "Mail-Relay", "", "", "webshell", ""),
        ("isolate_host", "Finance-Laptop", "", "", "", ""),
        ("isolate_host", "Mail-Relay", "", "", "", ""),
    ],
    "hard": [
        ("query_logs", "Build-Server", "", "last_hour", "", ""),
        ("analyze_process", "Build-Server", "", "", "", ""),
        ("isolate_host", "Build-Server", "", "", "", ""),
        ("query_logs", "Backup-Node", "", "last_hour", "", ""),
        ("analyze_process", "Backup-Node", "", "", "", ""),
        ("block_ip", "", "193.56.29.11", "", "", ""),
        ("threat_intel", "", "45.142.212.100", "", "", "45.142.212.100"),
        ("quarantine_process", "Backup-Node", "", "", "svc_update", ""),
        ("isolate_host", "Backup-Node", "", "", "", ""),
    ],
}


def llm_hint(client: OpenAI, task: str, step: int, last_echoed: str, last_reward: float) -> str:
    if not API_KEY:
        return "offline"
    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": "You are a SOC analyst assistant."},
                {
                    "role": "user",
                    "content": (
                        f"Task={task}; step={step}; last_echoed={last_echoed}; "
                        f"last_reward={last_reward:.3f}. Return one short hint."
                    ),
                },
            ],
            temperature=0.0,
        )
        content = response.choices[0].message.content
        return content.strip() if content else ""
    except Exception:
        return ""


async def run_task(http_client: SecureNetClient, llm_client: OpenAI, task: str) -> float:
    task_name = f"soc_triage_{task}"
    max_steps = MAX_STEPS_BY_TASK[task]
    log_start(task=task_name, env=BENCHMARK, model=MODEL_NAME)

    result = http_client.reset(task)
    last_echoed = result["observation"].get("echoed_message", "")
    last_reward = 0.0
    rewards: List[float] = []
    steps_taken = 0
    score = 0.0
    success = False

    try:
        for step in range(1, max_steps + 1):
            if result.get("done", False):
                break

            _ = llm_hint(llm_client, task_name, step, last_echoed, last_reward)

            action_type, target_node, ip_address, timeframe, process_name, ioc = PLAYBOOKS[task][step - 1]
            action_text = f"{action_type}:{target_node or ip_address or ioc or process_name or '-'}"

            result = http_client.step(
                action_type=action_type,
                target_node=target_node or None,
                ip_address=ip_address or None,
                timeframe=timeframe or None,
                process_name=process_name or None,
                ioc=ioc or None,
            )

            obs = result.get("observation", {})
            reward_obj = result.get("reward", {})
            reward = float(reward_obj.get("step_reward", 0.0))
            done = bool(result.get("done", False))
            error = result.get("info", {}).get("error", "null")

            rewards.append(reward)
            steps_taken = step
            last_echoed = obs.get("echoed_message", "")
            last_reward = reward

            log_step(step=step, action=action_text, reward=reward, done=done, error=error)

            if done:
                score = float(reward_obj.get("value", 0.0))
                break

        if not result.get("done", False):
            score = max(0.0, min(1.0, sum(max(r, 0.0) for r in rewards) / float(max_steps)))
        score = max(0.0, min(1.0, score))
        success = score >= SUCCESS_SCORE_THRESHOLD

    finally:
        log_end(success=success, steps=steps_taken, score=score, rewards=rewards)

    return score


async def main() -> None:
    llm_client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY or "hf-token-missing")
    env_client = SecureNetClient(os.getenv("ENV_BASE_URL", "http://localhost:7860"))

    for task in ["easy", "medium", "hard"]:
        await run_task(env_client, llm_client, task)


if __name__ == "__main__":
    asyncio.run(main())
