import re
import shlex
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import paramiko


# Настройки автотеста. Изменяйте под нормальную нагрузку контроллера.
MAX_FILE_SIZE_MB = 100
SPAM_TOTAL_COUNT = 100
SPAM_TOTAL_RATIO = 0.20
SPAM_BURST_COUNT = 20
SPAM_BURST_WINDOW_SECONDS = 60
REMOTE_LOG_DIR = "/var/log"
BASE_DIR = Path(__file__).resolve().parent


@dataclass(frozen=True)
class LogSpec:
    name: str
    candidates: tuple[str, ...]
    utc: bool = False


LOG_SPECS = [
    LogSpec("abak_power", ("abak_power", "abak_power.log")),
    LogSpec("abak_io", ("abakbbb_io", "abakbbb_io.log", "abak_io", "abak_io.log")),
    LogSpec("canmanager", ("canmanager", "canmanager.log")),
    LogSpec("runtime_log", ("runtime_log", "codesyscontrol", "runtime_log.log", "codesyscontrol.log"), utc=True),
    LogSpec("syslog", ("syslog",)),
    LogSpec("kern", ("kern", "kern.log")),
    LogSpec("daemon", ("daemon", "daemon.log")),
    LogSpec("xprofibus", ("xprofibus", "xprofibus.log")),
    LogSpec("abakrt", ("abakrt", "abakrt.log")),
    LogSpec("abak_opc", ("abak_opc", "abak_opc.log")),
]

KERNEL_ERROR_PATTERNS = [
    r"kernel BUG at",
    r"Internal error:\s*Oops",
    r"Kernel panic",
    r"Unable to handle kernel",
    r"Oops - BUG",
]
OVERFLOW_PATTERNS = [
    r"No space left on device",
    r"disk full",
    r"log(?: file)? (?:overflow|is full)",
]
ISO_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
)


@dataclass
class SpamFinding:
    count: int
    max_burst: int
    example: str
    reasons: list[str] = field(default_factory=list)


@dataclass
class LogResult:
    requested_name: str
    remote_path: str = ""
    content: str | None = None
    size_bytes: int = 0
    read_error: str = ""
    issues: list[str] = field(default_factory=list)
    spam: list[SpamFinding] = field(default_factory=list)
    top_messages: list[tuple[int, str]] = field(default_factory=list)

    @property
    def line_count(self) -> int:
        return len(self.content.splitlines()) if self.content is not None else 0


class ControllerSSH:
    def __init__(self, host: str, port: int, username: str, password: str):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.client: paramiko.SSHClient | None = None

    def connect(self) -> None:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            timeout=10,
            banner_timeout=10,
            auth_timeout=10,
            allow_agent=False,
            look_for_keys=False,
        )
        self.client = client

    def close(self) -> None:
        if self.client is not None:
            self.client.close()
            self.client = None

    def prepare_command(self, command: str) -> tuple[str, str | None]:
        """root работает напрямую; все остальные пользователи — только через sudo."""
        if self.username == "root":
            return command, None
        wrapped = f"sudo -S -p '' bash -lc {shlex.quote(command)}"
        return wrapped, f"{self.password}\n"

    def execute(self, command: str, timeout: int = 120) -> tuple[int, str, str]:
        if self.client is None:
            raise RuntimeError("SSH не подключён")
        remote_command, input_data = self.prepare_command(command)
        stdin, stdout, stderr = self.client.exec_command(remote_command, timeout=timeout)
        if input_data is not None:
            stdin.write(input_data)
            stdin.flush()
            stdin.channel.shutdown_write()
        output = stdout.read().decode("utf-8", errors="replace")
        error = stderr.read().decode("utf-8", errors="replace")
        status = stdout.channel.recv_exit_status()
        return status, output, error


def parse_timestamp(line: str) -> float | None:
    """Возвращает время для расчёта частоты. Не смешивает время разных файлов."""
    match = ISO_TIMESTAMP.match(line)
    if not match:
        return None
    try:
        value = match.group(0).replace(",", ".").replace("Z", "+00:00")
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except ValueError:
        return None


def normalize_message(line: str) -> str:
    """Убирает метки времени, PID и числа, чтобы найти повторяющийся текст."""
    message = ISO_TIMESTAMP.sub("", line, count=1).strip()
    message = re.sub(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+", "", message)
    message = re.sub(r"\[\s*\d+(?:\.\d+)?\]", "[]", message)
    message = re.sub(r"\[PID=\d+\]|\[\d+\]", "[]", message)
    message = re.sub(r"0x[0-9a-fA-F]+", "<HEX>", message)
    message = re.sub(r"\b\d+\b", "<N>", message)
    return re.sub(r"\s+", " ", message).strip()


def _max_burst(timestamps: list[float]) -> int:
    if not timestamps:
        return 0
    timestamps.sort()
    maximum = 0
    left = 0
    for right, timestamp in enumerate(timestamps):
        while timestamp - timestamps[left] > SPAM_BURST_WINDOW_SECONDS:
            left += 1
        maximum = max(maximum, right - left + 1)
    return maximum


def find_spam(content: str) -> tuple[list[SpamFinding], list[tuple[int, str]]]:
    counts: Counter[str] = Counter()
    examples: dict[str, str] = {}
    timestamps: dict[str, list[float]] = defaultdict(list)

    for line in content.splitlines():
        if not line.strip():
            continue
        normalized = normalize_message(line) or "<пустое сообщение>"
        counts[normalized] += 1
        examples.setdefault(normalized, line.strip())
        timestamp = parse_timestamp(line)
        if timestamp is not None:
            timestamps[normalized].append(timestamp)

    findings = []
    total_lines = sum(counts.values())
    for normalized, count in counts.items():
        burst = _max_burst(timestamps[normalized])
        reasons = []
        if count >= SPAM_TOTAL_COUNT and not timestamps[normalized]:
            reasons.append(f"{count} повторов без меток времени")
        elif count >= SPAM_TOTAL_COUNT and count / total_lines >= SPAM_TOTAL_RATIO:
            reasons.append(f"{count} повторов ({count / total_lines:.0%} файла)")
        if burst >= SPAM_BURST_COUNT:
            reasons.append(f"{burst} повторов за {SPAM_BURST_WINDOW_SECONDS} с")
        if reasons:
            findings.append(SpamFinding(count, burst, examples[normalized], reasons))

    findings.sort(key=lambda finding: finding.count, reverse=True)
    top_messages = [
        (count, examples[normalized])
        for normalized, count in counts.most_common(5)
    ]
    return findings, top_messages


def analyze_log(spec: LogSpec, result: LogResult) -> None:
    if result.content is None:
        return
    if result.size_bytes > MAX_FILE_SIZE_MB * 1024 * 1024:
        result.issues.append(
            f"размер {result.size_bytes / 1024 / 1024:.1f} МБ превышает {MAX_FILE_SIZE_MB} МБ"
        )

    result.spam, result.top_messages = find_spam(result.content)
    for finding in result.spam:
        result.issues.append("спам: " + "; ".join(finding.reasons))

    if spec.name == "kern":
        for line_number, line in enumerate(result.content.splitlines(), start=1):
            if any(re.search(pattern, line, re.IGNORECASE) for pattern in KERNEL_ERROR_PATTERNS):
                result.issues.append(f"ошибка ядра, строка {line_number}: {line.strip()}")

    for line_number, line in enumerate(result.content.splitlines(), start=1):
        if any(re.search(pattern, line, re.IGNORECASE) for pattern in OVERFLOW_PATTERNS):
            result.issues.append(f"переполнение, строка {line_number}: {line.strip()}")


def find_remote_log(ssh: ControllerSSH, spec: LogSpec) -> tuple[str, int, str]:
    for candidate in spec.candidates:
        path = f"{REMOTE_LOG_DIR}/{candidate}"
        quoted = shlex.quote(path)
        command = f"if [ -f {quoted} ]; then stat -c '%s' -- {quoted}; else exit 3; fi"
        status, output, error = ssh.execute(command)
        if status == 0:
            return path, int(output.strip()), ""
        if status != 3:
            return "", 0, f"{path}: {error.strip() or 'ошибка проверки файла'}"

        find_command = (
            f"find {shlex.quote(REMOTE_LOG_DIR)} -maxdepth 3 -type f "
            f"-name {shlex.quote(candidate)} -print -quit"
        )
        status, output, error = ssh.execute(find_command)
        if status != 0:
            return "", 0, f"поиск {candidate}: {error.strip() or 'ошибка поиска'}"
        if output.strip():
            path = output.strip().splitlines()[0]
            status, output, error = ssh.execute(f"stat -c '%s' -- {shlex.quote(path)}")
            if status == 0:
                return path, int(output.strip()), ""
            return "", 0, f"{path}: {error.strip() or 'ошибка проверки файла'}"
    return "", 0, f"файл не найден: {', '.join(spec.candidates)}"


def collect_and_analyze(ssh: ControllerSSH, run_dir: Path) -> list[LogResult]:
    results = []
    raw_dir = run_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    status, listing, listing_error = ssh.execute(
        f"find {shlex.quote(REMOTE_LOG_DIR)} -maxdepth 3 -type f -printf '%P\\n' | sort"
    )
    listing_content = listing if status == 0 else f"Ошибка получения списка: {listing_error}"
    (run_dir / "var_log_files.txt").write_text(listing_content, encoding="utf-8")

    for spec in LOG_SPECS:
        result = LogResult(spec.name)
        path, size, error = find_remote_log(ssh, spec)
        result.remote_path = path
        result.size_bytes = size
        if error:
            result.read_error = error
        else:
            status, output, read_error = ssh.execute(f"cat -- {shlex.quote(path)}")
            if status != 0:
                result.read_error = read_error.strip() or "ошибка чтения"
            else:
                result.content = output
                (raw_dir / spec.name).write_text(output, encoding="utf-8")
                analyze_log(spec, result)

        if result.issues:
            status_text = "ОШИБКА"
        elif result.read_error:
            status_text = "НЕ ПРОВЕРЕНО"
        elif result.line_count == 0:
            status_text = "OK (пустой)"
        else:
            status_text = "OK"
        print(f"{spec.name:<15} {status_text:<16} строк: {result.line_count:<8} размер: {size} байт")
        if result.read_error:
            print(f"  ВНИМАНИЕ: {result.read_error}")
            print("  Пришлите это сообщение и файл var_log_files.txt для исправления.")
        results.append(result)
    return results


def save_report(run_dir: Path, host: str, username: str, results: list[LogResult], overall: str) -> None:
    lines = [
        "АВТОТЕСТ ЛОГОВ КОНТРОЛЛЕРА НА СПАМ И ПЕРЕПОЛНЕНИЕ",
        "",
        f"Дата: {datetime.now():%Y-%m-%d %H:%M:%S}",
        f"Контроллер: {host}",
        f"Пользователь SSH: {username}",
        "runtime_log/codesyscontrol: время в файле указано по UTC",
        f"Пороги: {SPAM_BURST_COUNT} повторов/{SPAM_BURST_WINDOW_SECONDS} с; "
        f"{SPAM_TOTAL_COUNT} повторов без меток или от {SPAM_TOTAL_RATIO:.0%} файла; {MAX_FILE_SIZE_MB} МБ",
        f"ИТОГ: {overall}",
        "",
    ]
    for result in results:
        lines.extend([
            "=" * 70,
            f"ФАЙЛ: {result.requested_name}",
            f"Путь: {result.remote_path or 'не найден'}",
            f"Размер: {result.size_bytes} байт; строк: {result.line_count}",
        ])
        if result.read_error:
            lines.append(f"НЕ ПРОВЕРЕНО: {result.read_error}")
        if not result.issues and not result.read_error:
            lines.append("Спам, переполнение и ошибки ядра не обнаружены.")
        for issue in result.issues:
            lines.append(f"ПРОБЛЕМА: {issue}")
        for finding in result.spam:
            lines.append(f"  Пример повтора ({finding.count} раз): {finding.example}")
        if result.top_messages:
            lines.append("  Наиболее частые сообщения:")
            for count, example in result.top_messages:
                lines.append(f"  {count} x {example}")
        lines.append("")
    (run_dir / "report.txt").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    print("АВТОТЕСТ ЛОГОВ: СПАМ, ПЕРЕПОЛНЕНИЕ, ОШИБКИ ЯДРА")
    host = input("IP-адрес [192.168.53.53]: ").strip() or "192.168.53.53"
    port = int(input("Порт SSH [22]: ").strip() or "22")
    username = input("Пользователь [root]: ").strip() or "root"
    password = input("Пароль: ")

    ssh = ControllerSSH(host, port, username, password)
    run_dir = BASE_DIR / "logs_spam" / f"{datetime.now():%Y-%m-%d_%H-%M-%S}_{host}"
    try:
        print("\nПодключение и автоматическая проверка...")
        ssh.connect()
        status, output, error = ssh.execute(f"cd {shlex.quote(REMOTE_LOG_DIR)} && pwd")
        if status != 0:
            raise RuntimeError(f"Каталог {REMOTE_LOG_DIR} недоступен: {error.strip()}")
        print(f"Проверяемый каталог: {output.strip()}")
        results = collect_and_analyze(ssh, run_dir)

        if any(result.issues for result in results):
            overall = "ТЕСТ НЕ ПРОЙДЕН"
            exit_code = 1
        elif any(result.read_error for result in results):
            overall = "НЕЗАВЕРШЕНО: часть файлов не проверена"
            exit_code = 2
        else:
            overall = "ТЕСТ ПРОЙДЕН"
            exit_code = 0

        save_report(run_dir, host, username, results, overall)
        print("\n" + overall)
        for result in results:
            for issue in result.issues:
                print(f"- {result.requested_name}: {issue}")
            for finding in result.spam:
                print(f"  Пример ({finding.count} повторов): {finding.example}")
        print(f"Отчёт и логи: {run_dir}")
        return exit_code
    except Exception as exc:
        print(f"ОШИБКА: {exc}")
        return 2
    finally:
        ssh.close()


if __name__ == "__main__":
    sys.exit(main())
