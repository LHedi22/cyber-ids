"""
Log parser: tails SNORT_ALERT_PATH and emits LogEvent objects via a queue.
"""

import json
import logging
import os
import queue
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime

from dotenv import load_dotenv

load_dotenv()

log = logging.getLogger(__name__)

SNORT_ALERT_PATH = os.getenv("SNORT_ALERT_PATH", "/data/snort_alerts.jsonl")
SNORT_TS_FORMAT = "%Y/%m/%d-%H:%M:%S.%f"
POLL_INTERVAL = 0.1  # seconds


@dataclass
class LogEvent:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    sid: int
    msg: str
    priority: int
    bytes: int
    raw: dict = field(repr=False)


def _parse_line(line: str) -> LogEvent | None:
    """Parse one JSONL line into a LogEvent; return None on any error."""
    try:
        obj = json.loads(line)
    except json.JSONDecodeError as exc:
        log.warning("Malformed JSON skipped: %s | error: %s", line[:120], exc)
        return None

    try:
        ts_raw = obj["timestamp"]
        # Snort microseconds field may have >6 digits; truncate to 6
        if "." in ts_raw:
            base, frac = ts_raw.split(".", 1)
            ts_raw = f"{base}.{frac[:6]}"
        timestamp = datetime.strptime(ts_raw, SNORT_TS_FORMAT)

        return LogEvent(
            timestamp=timestamp,
            src_ip=str(obj["src_addr"]),
            dst_ip=str(obj["dst_addr"]),
            src_port=int(obj["src_port"]),
            dst_port=int(obj["dst_port"]),
            proto=str(obj["proto"]),
            sid=int(obj["sid"]),
            msg=str(obj["msg"]),
            priority=int(obj["priority"]),
            bytes=int(obj["bytes"]),
            raw=obj,
        )
    except (KeyError, ValueError, TypeError) as exc:
        log.warning("Incomplete/invalid event skipped: %s | error: %s", line[:120], exc)
        return None


class LogTailer:
    """
    Watches a JSONL file in a daemon thread.
    Seeks to EOF on startup, then polls every POLL_INTERVAL seconds for new lines.
    Emits LogEvent objects into the provided queue.Queue.
    Handles file rotation: if the file disappears, waits and re-opens when it returns.
    """

    def __init__(self, path: str, event_queue: queue.Queue) -> None:
        self.path = path
        self.event_queue = event_queue
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name="log-tailer")
        self._counter_lock = threading.Lock()
        self._events_parsed = 0

    @property
    def events_parsed(self) -> int:
        with self._counter_lock:
            return self._events_parsed

    def _increment(self) -> None:
        with self._counter_lock:
            self._events_parsed += 1

    def start(self) -> None:
        self._thread.start()
        log.info("LogTailer started on %s", self.path)

    def stop(self) -> None:
        self._stop.set()

    def _open_file(self):
        """Block until the file exists, then open it and seek to EOF."""
        while not self._stop.is_set():
            if os.path.exists(self.path):
                try:
                    f = open(self.path, "r", encoding="utf-8")
                    f.seek(0, 2)  # seek to end
                    log.info("Tailing %s from EOF (offset=%d)", self.path, f.tell())
                    return f
                except OSError as exc:
                    log.warning("Could not open %s: %s — retrying", self.path, exc)
            else:
                log.info("Waiting for %s to appear...", self.path)
            time.sleep(1.0)
        return None

    def _run(self) -> None:
        f = self._open_file()
        if f is None:
            return  # stop() called while waiting

        try:
            while not self._stop.is_set():
                line = f.readline()

                if line:
                    line = line.strip()
                    if line:
                        event = _parse_line(line)
                        if event is not None:
                            self.event_queue.put(event)
                            self._increment()
                    continue  # immediately try next line without sleeping

                # No new data — check for rotation
                if not os.path.exists(self.path):
                    log.warning("File %s disappeared, waiting for rotation...", self.path)
                    f.close()
                    f = self._open_file()
                    if f is None:
                        break
                    continue

                # Check if the file was truncated (rotation via truncate)
                try:
                    current_size = os.path.getsize(self.path)
                    current_pos = f.tell()
                    if current_size < current_pos:
                        log.info("File truncated — re-opening from start")
                        f.close()
                        f = open(self.path, "r", encoding="utf-8")
                        continue
                except OSError:
                    pass

                time.sleep(POLL_INTERVAL)
        finally:
            try:
                f.close()
            except Exception:
                pass
            log.info("LogTailer stopped")


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import tempfile

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")

    VALID_LINE = json.dumps({
        "timestamp": "2026/04/25-14:32:01.123456",
        "src_addr": "10.0.0.1",
        "dst_addr": "192.168.1.1",
        "src_port": 54321,
        "dst_port": 22,
        "proto": "TCP",
        "sid": 1000001,
        "gid": 1,
        "rev": 1,
        "msg": "SSH Brute Force",
        "priority": 1,
        "bytes": 512,
        "action": "alert",
    })

    def _fail(reason: str) -> None:
        print(f"FAIL: {reason}")
        raise SystemExit(1)

    # Write the file BEFORE starting the tailer so we can seek to start
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
    ) as tmp:
        tmp_path = tmp.name

    eq: queue.Queue = queue.Queue()
    tailer = LogTailer(tmp_path, eq)

    # Monkeypatch _open_file to seek to START (not EOF) for self-test readability
    original_open = tailer._open_file

    def _open_from_start():
        import builtins
        while not tailer._stop.is_set():
            if os.path.exists(tailer.path):
                f = builtins.open(tailer.path, "r", encoding="utf-8")
                f.seek(0)
                return f
            time.sleep(0.1)
        return None

    tailer._open_file = _open_from_start  # type: ignore[method-assign]
    tailer.start()

    # Give the thread a moment to open the file
    time.sleep(0.15)

    # Write 10 valid + 2 malformed lines
    with open(tmp_path, "a", encoding="utf-8") as f:
        for _ in range(10):
            f.write(VALID_LINE + "\n")
        f.write("this is not json\n")
        f.write('{"incomplete": true}\n')  # missing required fields
        f.flush()

    # Collect events for up to 3 seconds
    received = []
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline and len(received) < 10:
        try:
            received.append(eq.get(timeout=0.2))
        except queue.Empty:
            pass

    tailer.stop()
    tailer._thread.join(timeout=2.0)  # wait for file handle to close before unlink
    os.unlink(tmp_path)

    if len(received) != 10:
        _fail(f"expected 10 LogEvents, got {len(received)}")

    if tailer.events_parsed != 10:
        _fail(f"events_parsed counter={tailer.events_parsed}, expected 10")

    for evt in received:
        if not isinstance(evt, LogEvent):
            _fail(f"queue item is not a LogEvent: {type(evt)}")
        if not isinstance(evt.timestamp, datetime):
            _fail(f"timestamp is not datetime: {evt.timestamp!r}")

    print("PASS: parser self-test")
