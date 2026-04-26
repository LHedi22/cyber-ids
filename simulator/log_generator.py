"""
Snort 3-format alert simulator.

Writes one JSON object per line to SNORT_ALERT_PATH, continuously cycling
through 5 attack scenarios with realistic normal-traffic padding (~90% normal).
When DEMO_MODE=false, exits immediately so real Snort can take over.
"""

import json
import logging
import os
import random
import time
from datetime import datetime, timezone

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [simulator] %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration (all from env, all with defaults)
# ---------------------------------------------------------------------------
SNORT_ALERT_PATH = os.getenv("SNORT_ALERT_PATH", "/data/snort_alerts.jsonl")
ATTACK_CYCLE_SECONDS = int(os.getenv("ATTACK_CYCLE_SECONDS", "30"))
NORMAL_EVENTS_PER_SECOND = float(os.getenv("NORMAL_EVENTS_PER_SECOND", "2.0"))
DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"

BRUTE_FORCE_THRESHOLD = int(os.getenv("BRUTE_FORCE_THRESHOLD", "5"))
PORT_SCAN_THRESHOLD = int(os.getenv("PORT_SCAN_THRESHOLD", "20"))
DATA_EXFIL_BYTES = int(os.getenv("DATA_EXFIL_BYTES", "10000"))

# IP pools
ATTACKER_IPS = [f"10.{random.randint(0,9)}.{random.randint(0,9)}.{i}" for i in range(1, 21)]
TARGET_IPS = [f"192.168.1.{i}" for i in range(1, 11)]
NORMAL_SRC_IPS = [f"172.16.{random.randint(0,5)}.{i}" for i in range(1, 31)]


# ---------------------------------------------------------------------------
# Schema builder
# ---------------------------------------------------------------------------

def _ts() -> str:
    """Current timestamp in Snort alert_json format."""
    return datetime.now(timezone.utc).strftime("%Y/%m/%d-%H:%M:%S.%f")


def make_event(
    src_addr: str,
    dst_addr: str,
    src_port: int,
    dst_port: int,
    proto: str,
    sid: int,
    msg: str,
    priority: int,
    bytes_: int,
    action: str = "alert",
) -> dict:
    return {
        "timestamp": _ts(),
        "src_addr": src_addr,
        "dst_addr": dst_addr,
        "src_port": src_port,
        "dst_port": dst_port,
        "proto": proto,
        "sid": sid,
        "gid": 1,
        "rev": 1,
        "msg": msg,
        "priority": priority,
        "bytes": bytes_,
        "action": action,
    }


def write_event(f, event: dict) -> None:
    """Atomic line write: encode -> write -> flush (single syscall for lines < 4096 B)."""
    f.write(json.dumps(event) + "\n")
    f.flush()


# ---------------------------------------------------------------------------
# Normal traffic generators
# ---------------------------------------------------------------------------

def normal_ssh_success() -> dict:
    return make_event(
        src_addr=random.choice(NORMAL_SRC_IPS),
        dst_addr=random.choice(TARGET_IPS),
        src_port=random.randint(49152, 65535),
        dst_port=22,
        proto="TCP",
        sid=2000001,
        msg="SSH Connection Established",
        priority=4,
        bytes_=random.randint(200, 800),
        action="allow",
    )


def normal_http_get() -> dict:
    return make_event(
        src_addr=random.choice(NORMAL_SRC_IPS),
        dst_addr=random.choice(TARGET_IPS),
        src_port=random.randint(49152, 65535),
        dst_port=random.choice([80, 443]),
        proto="TCP",
        sid=2000002,
        msg="HTTP GET Request",
        priority=4,
        bytes_=random.randint(300, 1200),
        action="allow",
    )


def normal_dns() -> dict:
    return make_event(
        src_addr=random.choice(NORMAL_SRC_IPS),
        dst_addr="192.168.1.1",
        src_port=random.randint(49152, 65535),
        dst_port=53,
        proto="UDP",
        sid=2000003,
        msg="DNS Query",
        priority=4,
        bytes_=random.randint(60, 200),
        action="allow",
    )


NORMAL_GENERATORS = [normal_ssh_success, normal_http_get, normal_dns]


def emit_normal(f) -> None:
    gen = random.choices(NORMAL_GENERATORS, weights=[2, 5, 3])[0]
    write_event(f, gen())


# ---------------------------------------------------------------------------
# Attack scenario generators
# ---------------------------------------------------------------------------

def scenario_ssh_brute_force(f) -> None:
    """SID 1000001: 20-60 failed SSH logins from one IP within 60 s."""
    attacker = random.choice(ATTACKER_IPS)
    target = random.choice(TARGET_IPS)
    count = random.randint(BRUTE_FORCE_THRESHOLD * 4, 60)
    log.info("ATTACK: SSH brute force from %s -> %s (%d attempts)", attacker, target, count)
    for _ in range(count):
        write_event(f, make_event(
            src_addr=attacker,
            dst_addr=target,
            src_port=random.randint(49152, 65535),
            dst_port=22,
            proto="TCP",
            sid=1000001,
            msg="SSH Brute Force Attempt",
            priority=1,
            bytes_=random.randint(400, 600),
        ))
        time.sleep(random.uniform(0.05, 0.15))


def scenario_sql_injection(f) -> None:
    """SID 1000002: HTTP POST with SQLi payload to port 80/443."""
    attacker = random.choice(ATTACKER_IPS)
    target = random.choice(TARGET_IPS)
    count = random.randint(3, 10)
    log.info("ATTACK: SQL injection from %s -> %s (%d requests)", attacker, target, count)
    for _ in range(count):
        write_event(f, make_event(
            src_addr=attacker,
            dst_addr=target,
            src_port=random.randint(49152, 65535),
            dst_port=random.choice([80, 443]),
            proto="TCP",
            sid=1000002,
            msg="SQL Injection Attempt Detected",
            priority=2,
            bytes_=random.randint(800, 2000),
        ))
        time.sleep(random.uniform(0.3, 0.8))


def scenario_port_scan(f) -> None:
    """SID 1000003: One IP hits 20+ unique dst_ports within 10 s."""
    attacker = random.choice(ATTACKER_IPS)
    target = random.choice(TARGET_IPS)
    ports = random.sample(range(1, 65535), PORT_SCAN_THRESHOLD + random.randint(1, 20))
    log.info("ATTACK: Port scan from %s -> %s (%d ports)", attacker, target, len(ports))
    for port in ports:
        write_event(f, make_event(
            src_addr=attacker,
            dst_addr=target,
            src_port=random.randint(49152, 65535),
            dst_port=port,
            proto="TCP",
            sid=1000003,
            msg="Port Scan Detected",
            priority=2,
            bytes_=random.randint(40, 80),
        ))
        time.sleep(random.uniform(0.01, 0.05))


def scenario_off_hours_access(f) -> None:
    """SID 1000004: Successful login during off-hours window."""
    attacker = random.choice(ATTACKER_IPS)
    target = random.choice(TARGET_IPS)
    log.info("ATTACK: Off-hours access from %s -> %s", attacker, target)
    write_event(f, make_event(
        src_addr=attacker,
        dst_addr=target,
        src_port=random.randint(49152, 65535),
        dst_port=22,
        proto="TCP",
        sid=1000004,
        msg="Off-Hours Successful Login",
        priority=3,
        bytes_=random.randint(300, 600),
    ))


def scenario_data_exfil(f) -> None:
    """SID 1000005: Large bytes_out to unknown external IP."""
    attacker = random.choice(ATTACKER_IPS)
    # Use an unknown external IP outside the normal target pool
    external_ip = f"203.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    count = random.randint(3, 8)
    log.info("ATTACK: Data exfil from %s -> %s (%d chunks)", attacker, external_ip, count)
    for _ in range(count):
        write_event(f, make_event(
            src_addr=attacker,
            dst_addr=external_ip,
            src_port=random.randint(49152, 65535),
            dst_port=random.choice([443, 8443, 4444]),
            proto="TCP",
            sid=1000005,
            msg="Possible Data Exfiltration",
            priority=2,
            bytes_=random.randint(DATA_EXFIL_BYTES, DATA_EXFIL_BYTES * 3),
        ))
        time.sleep(random.uniform(0.2, 0.6))


ATTACK_SCENARIOS = [
    scenario_ssh_brute_force,
    scenario_sql_injection,
    scenario_port_scan,
    scenario_off_hours_access,
    scenario_data_exfil,
]


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run(output_path: str = SNORT_ALERT_PATH) -> None:
    if not DEMO_MODE:
        log.info("DEMO_MODE=false -- simulator exiting, real Snort active")
        return

    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    log.info("Simulator starting -> %s (cycle=%ds)", output_path, ATTACK_CYCLE_SECONDS)

    scenario_index = 0
    normal_interval = 1.0 / NORMAL_EVENTS_PER_SECOND

    with open(output_path, "a", buffering=1) as f:  # line-buffered
        last_attack_time = time.monotonic() - ATTACK_CYCLE_SECONDS  # fire first attack immediately

        while True:
            now = time.monotonic()

            if now - last_attack_time >= ATTACK_CYCLE_SECONDS:
                scenario = ATTACK_SCENARIOS[scenario_index % len(ATTACK_SCENARIOS)]
                scenario(f)
                scenario_index += 1
                last_attack_time = time.monotonic()

            # Emit normal traffic at configured rate between attacks
            normal_count = max(1, int(ATTACK_CYCLE_SECONDS * NORMAL_EVENTS_PER_SECOND // 10))
            for _ in range(normal_count):
                emit_normal(f)
                time.sleep(normal_interval)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import tempfile

    REQUIRED_FIELDS = {
        "timestamp", "src_addr", "dst_addr", "src_port", "dst_port",
        "proto", "sid", "gid", "rev", "msg", "priority", "bytes", "action",
    }

    def _fail(reason: str) -> None:
        print(f"FAIL: {reason}")
        raise SystemExit(1)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as tmp:
        tmp_path = tmp.name

    os.environ["DEMO_MODE"] = "true"

    # Write all 5 attack scenarios + 10 normal events = well over 20 lines
    with open(tmp_path, "a", buffering=1) as f:
        for scenario in ATTACK_SCENARIOS:
            scenario(f)
        for _ in range(10):
            emit_normal(f)

    with open(tmp_path) as f:
        lines = [line.strip() for line in f if line.strip()]

    if len(lines) < 20:
        _fail(f"expected >=20 lines, got {len(lines)}")

    sids_seen = set()
    for i, line in enumerate(lines):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            _fail(f"line {i+1} is not valid JSON: {e}")

        missing = REQUIRED_FIELDS - obj.keys()
        if missing:
            _fail(f"line {i+1} missing fields: {missing}")

        sids_seen.add(obj["sid"])

    if len(sids_seen) < 3:
        _fail(f"expected >=3 distinct SIDs, got {sids_seen}")

    os.unlink(tmp_path)
    print("PASS: simulator self-test")
