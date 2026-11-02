import getpass
import re
import shlex
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import paramiko


BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = "/var/log"
CURRENT_BOOT_TOLERANCE = timedelta(seconds=5)

BOOT_PATTERNS = {
    "auth.log": [
        r"systemd-logind.*Watching system buttons",
        r"systemd-logind.*New seat seat0",
        r"sshd.*Server listening on",
    ],
    "daemon.log": [
        r"systemd-networkd.*Link UP",
        r"lan\d+: Link UP",
    ],
    "debug": [
        r"VCC_5V_BOOST:.*mV.*enabled",
        r"VCC_3V3_IN:.*mV.*enabled",
        r"vdd_cpu:.*mV.*enabled",
        r"reg-fixed-voltage.*supplying",
    ],
    "kern.log": [
        r"kernel.*Booting Linux on physical CPU",
    ],
    "syslog": [
        r"systemd.*Started PostgreSQL",
        r"connmand.*newlink.*index",
        r"PostgreSQL Cluster.*main",
    ],
}

SYSLOG_TIMESTAMP = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2})"
)
MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


@dataclass
class BootEvent:
    log_name: str
    line_number: int
    line: str
    timestamp: datetime | None


def parse_log_timestamp(line: str, reference: datetime) -> datetime | None:
    """Читает ISO- и syslog-метки. Для syslog выбирает ближайший год."""
    try:
        iso_match = re.match(
            r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
            line,
        )
        if iso_match:
            value = iso_match.group(0).replace(",", ".").replace("Z", "+00:00")
            parsed = datetime.fromisoformat(value)
            if parsed.tzinfo is not None:
                parsed = parsed.astimezone().replace(tzinfo=None)
            return parsed
    except ValueError:
        return None

    match = SYSLOG_TIMESTAMP.match(line)
    if not match or match.group("month") not in MONTHS:
        return None

    clock = datetime.strptime(match.group("clock"), "%H:%M:%S").time()
    candidates = []
    for year in (reference.year - 1, reference.year, reference.year + 1):
        try:
            candidates.append(datetime(
                year,
                MONTHS[match.group("month")],
                int(match.group("day")),
                clock.hour,
                clock.minute,
                clock.second,
            ))
        except ValueError:
            pass

    return min(candidates, key=lambda value: abs(value - reference)) if candidates else None


def find_boot_events(logs: dict[str, str], reference: datetime) -> list[BootEvent]:
    events = []
    for log_name, content in logs.items():
        for line_number, line in enumerate(content.splitlines(), start=1):
            if any(re.search(pattern, line, re.IGNORECASE)
                   for pattern in BOOT_PATTERNS[log_name]):
                events.append(BootEvent(
                    log_name=log_name,
                    line_number=line_number,
                    line=line.strip(),
                    timestamp=parse_log_timestamp(line, reference),
                ))
    return events


def classify_events(
    events: list[BootEvent],
    power_off: datetime,
    power_on: datetime,
    current_boot: datetime,
) -> tuple[list[BootEvent], list[BootEvent], list[BootEvent]]:
    """Возвращает нарушения, события текущей загрузки и строки без даты."""
    violations = []
    current_events = []
    undated = []
    current_boot_start = current_boot - CURRENT_BOOT_TOLERANCE

    for event in events:
        if event.timestamp is None:
            undated.append(event)
        elif event.timestamp >= current_boot_start:
            current_events.append(event)
        elif power_off <= event.timestamp <= power_on:
            violations.append(event)

    return violations, current_events, undated


class ControllerSSH:
    def __init__(self, host: str, port: int, username: str, password: str):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.client: paramiko.SSHClient | None = None

    def connect(self, timeout: int = 10) -> None:
        self.close()
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        self.client = client

    def close(self) -> None:
        if self.client is not None:
            self.client.close()
            self.client = None

    def execute(self, command: str, timeout: int = 30) -> tuple[int, str, str]:
        if self.client is None:
            raise RuntimeError("SSH не подключён")
        _, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        output = stdout.read().decode("utf-8", errors="replace")
        error = stderr.read().decode("utf-8", errors="replace")
        status = stdout.channel.recv_exit_status()
        return status, output, error

    def read_logs(self, destination: Path) -> tuple[dict[str, str], list[str]]:
        destination.mkdir(parents=True, exist_ok=True)
        logs = {}
        errors = []

        for log_name in BOOT_PATTERNS:
            remote_path = f"{LOG_DIR}/{log_name}"
            status, output, error = self.execute(f"cat -- {shlex.quote(remote_path)}")
            if status == 0:
                logs[log_name] = output
                (destination / log_name).write_text(output, encoding="utf-8")
                print(f"  {log_name}: {len(output.splitlines())} строк")
            else:
                message = f"{log_name}: {error.strip() or 'не удалось прочитать файл'}"
                errors.append(message)
                print(f"  {message}")

        return logs, errors

    def get_boot_info(self) -> tuple[datetime, datetime]:
        status, output, error = self.execute("date +%s; cut -d' ' -f1 /proc/uptime")
        lines = output.strip().splitlines()
        if status != 0 or len(lines) < 2:
            raise RuntimeError(f"Не удалось получить время загрузки: {error.strip()}")
        remote_now = datetime.fromtimestamp(int(lines[0].strip()))
        current_boot = remote_now - timedelta(seconds=float(lines[1].strip()))
        return remote_now, current_boot


def wait_for_enter(message: str) -> datetime:
    print("\n" + "=" * 70)
    print(message)
    input("Нажмите ENTER сразу после выполнения действия...")
    return datetime.now()


def wait_for_reconnect(ssh: ControllerSSH, attempts: int = 60) -> bool:
    print("\nОжидаю загрузку контроллера и восстановление SSH...")
    for attempt in range(1, attempts + 1):
        try:
            ssh.connect(timeout=5)
            print(f"SSH восстановлен с попытки {attempt}.")
            return True
        except Exception:
            if attempt == attempts:
                break
            time.sleep(5)
    return False


def format_event(event: BootEvent) -> str:
    timestamp = event.timestamp.strftime("%Y-%m-%d %H:%M:%S") if event.timestamp else "дата не распознана"
    return f"[{timestamp}] {event.log_name}:{event.line_number}: {event.line}"


def save_report(
    report_path: Path,
    power_off: datetime,
    power_on: datetime,
    remote_now: datetime,
    current_boot: datetime,
    violations: list[BootEvent],
    current_events: list[BootEvent],
    undated: list[BootEvent],
    read_errors: list[str],
    result: str,
) -> None:
    lines = [
        "ПРОВЕРКА ОТСУТСТВИЯ ЗАГРУЗОК КОНТРОЛЛЕРА НА ИОНИСТОРАХ",
        "",
        f"Питание отключено: {power_off:%Y-%m-%d %H:%M:%S}",
        f"Питание подано:    {power_on:%Y-%m-%d %H:%M:%S}",
        f"Время контроллера при проверке: {remote_now:%Y-%m-%d %H:%M:%S}",
        f"Начало текущей загрузки:        {current_boot:%Y-%m-%d %H:%M:%S}",
        f"Результат: {result}",
        "",
        f"Признаков текущей штатной загрузки: {len(current_events)}",
        f"Признаков паразитной загрузки:      {len(violations)}",
        f"Строк загрузки без распознанной даты: {len(undated)}",
        "",
        "НАРУШЕНИЯ:",
    ]
    lines.extend(format_event(event) for event in violations)
    if not violations:
        lines.append("Нет")
    lines.extend(["", "СТРОКИ БЕЗ ДАТЫ:"])
    lines.extend(format_event(event) for event in undated)
    if not undated:
        lines.append("Нет")
    lines.extend(["", "ОШИБКИ ЧТЕНИЯ ЛОГОВ:"])
    lines.extend(read_errors or ["Нет"])
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def get_connection_params() -> tuple[str, int, str, str]:
    print("\nНАСТРОЙКА SSH")
    host = input("IP-адрес контроллера [192.168.1.100]: ").strip() or "192.168.1.100"
    port = int(input("Порт SSH [22]: ").strip() or "22")
    username = input("Пользователь [root]: ").strip() or "root"
    password = getpass.getpass("Пароль: ")
    return host, port, username, password


def main() -> int:
    print("=" * 70)
    print("ПРОВЕРКА ОТСУТСТВИЯ ЗАГРУЗОК КОНТРОЛЛЕРА НА ИОНИСТОРАХ")
    print("=" * 70)

    host, port, username, password = get_connection_params()
    ssh = ControllerSSH(host, port, username, password)
    run_dir = BASE_DIR / "logs" / f"{datetime.now():%Y-%m-%d_%H-%M-%S}_{host.replace(':', '_')}"

    try:
        print("\nПодключаюсь к контроллеру...")
        ssh.connect()
        print("Подключение установлено.")

        input("\nСинхронизируйте время в конфигураторе, затем нажмите ENTER...")
        status, controller_date, error = ssh.execute("date '+%Y-%m-%d %H:%M:%S'")
        if status != 0:
            raise RuntimeError(f"Не удалось проверить время контроллера: {error.strip()}")
        print(f"Время контроллера: {controller_date.strip()}")
        print(f"Время ПК:          {datetime.now():%Y-%m-%d %H:%M:%S}")

        print("\nСохраняю логи ДО отключения питания:")
        _, before_errors = ssh.read_logs(run_dir / "before")
        if before_errors:
            print("Некоторые логи недоступны. Они записаны в отчёт после теста.")

        power_off = wait_for_enter(
            "ОТКЛЮЧИТЕ ПИТАНИЕ контроллера.\n"
            "Сразу после отключения нажмите ENTER — это время границы проверки."
        )
        ssh.close()
        print(f"Зафиксировано отключение: {power_off:%Y-%m-%d %H:%M:%S}")

        print("\nДождитесь полного выключения и отсутствия индикации (обычно 3–5 минут).")
        input("Когда все индикаторы погаснут, нажмите ENTER...")

        power_on = wait_for_enter("ПОДАЙТЕ ПИТАНИЕ на контроллер.")
        print(f"Зафиксировано включение: {power_on:%Y-%m-%d %H:%M:%S}")

        if not wait_for_reconnect(ssh):
            print("\nНЕЗАВЕРШЕНО: SSH не восстановился в течение 5 минут.")
            print("Логи до отключения сохранены. После загрузки контроллера проверку нужно повторить.")
            return 2

        time.sleep(5)
        remote_now, current_boot = ssh.get_boot_info()
        print(f"Текущая загрузка началась: {current_boot:%Y-%m-%d %H:%M:%S}")

        print("\nСохраняю логи ПОСЛЕ включения:")
        after_logs, read_errors = ssh.read_logs(run_dir / "after")
        events = find_boot_events(after_logs, remote_now)
        violations, current_events, undated = classify_events(
            events, power_off, power_on, current_boot
        )

        if not after_logs or not current_events:
            result = "НЕЗАВЕРШЕНО"
            reason = "Не удалось подтвердить текущую загрузку по логам; автоматический вывод невозможен."
        elif undated:
            result = "ТРЕБУЕТСЯ РУЧНАЯ ПРОВЕРКА"
            reason = "Есть строки загрузки без распознанной даты."
        elif violations:
            result = "ТЕСТ НЕ ПРОЙДЕН"
            reason = "Обнаружены загрузки между отключением и подачей питания."
        else:
            result = "ТЕСТ ПРОЙДЕН"
            reason = "В проверяемом периоде признаков загрузки не найдено."

        print("\n" + "=" * 70)
        print(result)
        print(reason)
        if violations:
            print("\nПодозрительные записи:")
            for event in violations:
                print(format_event(event))
        if undated:
            print("\nСтроки, требующие ручной проверки:")
            for event in undated:
                print(format_event(event))

        save_report(
            run_dir / "report.txt", power_off, power_on, remote_now, current_boot,
            violations, current_events, undated, before_errors + read_errors, result,
        )
        print(f"\nЛоги и отчёт сохранены: {run_dir}")
        return 1 if violations else (0 if result == "ТЕСТ ПРОЙДЕН" else 2)

    except KeyboardInterrupt:
        print("\nТест прерван пользователем.")
        return 2
    except Exception as exc:
        print(f"\nОШИБКА: {exc}")
        print(f"Сохранённые файлы: {run_dir}")
        return 2
    finally:
        ssh.close()


if __name__ == "__main__":
    sys.exit(main())
