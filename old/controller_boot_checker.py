import re
import os
import paramiko
from datetime import datetime, timedelta
import time
import sys


class ControllerBootChecker:
    def __init__(self):
        self.ssh_client = None
        self.ssh_params = {}
        self.saved_logs_before = {}
        self.log_dir = "/var/log"

        self.boot_patterns = {
            'auth.log': [
                r'systemd-logind.*Watching system buttons',
                r'systemd-logind.*New seat seat0',
                r'sshd.*Server listening on',
            ],
            'daemon.log': [
                r'systemd-networkd.*Link UP',
                r'lan\d+: Link UP',
            ],
            'debug': [
                r'VCC_5V_BOOST:.*mV.*enabled',
                r'VCC_3V3_IN:.*mV.*enabled',
                r'vdd_cpu:.*mV.*enabled',
                r'reg-fixed-voltage.*supplying',
            ],
            'kern.log': [
                r'Booting Linux on physical CPU',
                r'kernel.*Booting Linux',
            ],
            'syslog': [
                r'systemd.*Started PostgreSQL',
                r'connmand.*newlink.*index',
                r'PostgreSQL Cluster.*main',
            ]
        }

    def get_ssh_params(self):
        """Получаем параметры SSH подключения"""
        print("\n" + "=" * 60)
        print("НАСТРОЙКА SSH ПОДКЛЮЧЕНИЯ")
        print("=" * 60)

        self.ssh_params = {
            'host': input("IP-адрес контроллера [192.168.1.100]: ") or "192.168.1.100",
            'port': int(input("Порт SSH [22]: ") or "22"),
            'username': input("Пользователь [root]: ") or "root",
            'password': input("Пароль: ")
        }

    def connect_ssh(self):
        """Подключение к контроллеру по SSH"""
        try:
            print(f"🔄 Подключаюсь к {self.ssh_params['host']}...")

            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            self.ssh_client.connect(
                hostname=self.ssh_params['host'],
                port=self.ssh_params['port'],
                username=self.ssh_params['username'],
                password=self.ssh_params['password'],
                timeout=10,
                banner_timeout=10,
                auth_timeout=10
            )

            print("✅ Подключение установлено!")
            return True

        except Exception as e:
            print(f"❌ Ошибка подключения: {e}")
            return False

    def execute_command(self, command):
        """Выполнение команды на контроллере"""
        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(command, timeout=10)
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')
            return output if output else error
        except Exception as e:
            print(f"Ошибка выполнения команды: {e}")
            return None

    def save_logs_before_poweroff(self):
        """Сохраняем логи ДО отключения питания"""
        print("\n" + "=" * 60)
        print("СОХРАНЕНИЕ ЛОГОВ ДО ОТКЛЮЧЕНИЯ")
        print("=" * 60)

        for log_name in self.boot_patterns.keys():
            file_path = f"{self.log_dir}/{log_name}"
            print(f"📥 Читаю {log_name}...")

            # Сохраняем последние 200 строк с временными метками
            command = f"""
            if [ -f {file_path} ]; then
                echo "===LAST_TIMESTAMP==="
                tail -n 200 {file_path} | grep -E '^[A-Z][a-z]{{2}} [0-9]' | tail -n 1
                echo "===CONTENT==="
                tail -n 200 {file_path}
            else
                echo "FILE_NOT_FOUND"
            fi
            """

            result = self.execute_command(command)

            if result and 'FILE_NOT_FOUND' not in result:
                # Парсим результат
                parts = result.split('===CONTENT===')
                timestamp_part = parts[0].replace('===LAST_TIMESTAMP===', '').strip()
                content = parts[1] if len(parts) > 1 else ''

                self.saved_logs_before[log_name] = {
                    'last_timestamp': timestamp_part,
                    'content': content
                }

                print(f"  ✅ Сохранено. Последняя запись: {timestamp_part}")
            else:
                print(f"  ⚠️  Файл не найден")
                self.saved_logs_before[log_name] = None

        # Сохраняем также в локальный файл на всякий случай
        with open('logs_backup.txt', 'w') as f:
            for name, data in self.saved_logs_before.items():
                if data:
                    f.write(f"\n=== {name} ===\n")
                    f.write(f"Last timestamp: {data['last_timestamp']}\n")
                    f.write(data['content'])

        print("\n💾 Логи сохранены в файл 'logs_backup.txt'")

    def sync_time(self):
        """Синхронизация времени"""
        print("\n" + "=" * 60)
        print("СИНХРОНИЗАЦИЯ ВРЕМЕНИ")
        print("=" * 60)

        current_time = datetime.now()
        time_str = current_time.strftime('%Y-%m-%d %H:%M:%S')

        # Устанавливаем время на контроллере
        print(f"🕐 Устанавливаю время: {time_str}")
        self.execute_command(f"date -s '{time_str}'")

        # Проверяем
        check = self.execute_command("date '+%Y-%m-%d %H:%M:%S'")
        print(f"  Время контроллера: {check.strip() if check else 'ошибка'}")

        return current_time

    def disconnect_ssh(self):
        """Отключаем SSH"""
        if self.ssh_client:
            try:
                self.ssh_client.close()
                print("🔌 SSH отключен")
            except:
                pass
            self.ssh_client = None

    def wait_for_controller_and_reconnect(self):
        """Ждем включения контроллера и подключаемся заново"""
        print("\n" + "=" * 60)
        print("ОЖИДАНИЕ ЗАГРУЗКИ КОНТРОЛЛЕРА")
        print("=" * 60)

        # Сначала ждем 30 секунд пока контроллер начнет загружаться
        print("⏳ Жду 30 секунд...")
        time.sleep(30)

        # Пробуем подключиться
        max_attempts = 30
        for attempt in range(max_attempts):
            print(f"🔄 Попытка подключения {attempt + 1}/{max_attempts}...")

            try:
                # Создаем новое SSH соединение
                self.ssh_client = paramiko.SSHClient()
                self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                self.ssh_client.connect(
                    hostname=self.ssh_params['host'],
                    port=self.ssh_params['port'],
                    username=self.ssh_params['username'],
                    password=self.ssh_params['password'],
                    timeout=5,
                    banner_timeout=5,
                    auth_timeout=5
                )

                print("✅ Контроллер загружен! Подключение восстановлено.")

                # Проверяем uptime чтобы убедиться что загрузка свежая
                uptime = self.execute_command("uptime -s")
                if uptime:
                    print(f"  Время загрузки системы: {uptime.strip()}")

                return True

            except Exception as e:
                if attempt < max_attempts - 1:
                    print(f"  Контроллер еще не готов. Жду 10 секунд...")
                    time.sleep(10)
                else:
                    print(f"❌ Не удалось подключиться после {max_attempts} попыток")
                    return False
            finally:
                if not self.ssh_client or not self.ssh_client.get_transport():
                    pass  # Продолжаем попытки

    def check_new_logs(self, power_off_time, power_on_time):
        """Проверяем новые записи в логах после включения"""
        print("\n" + "=" * 60)
        print("ПРОВЕРКА ЛОГОВ ПОСЛЕ ВКЛЮЧЕНИЯ")
        print("=" * 60)

        violations = []

        for log_name in self.boot_patterns.keys():
            file_path = f"{self.log_dir}/{log_name}"
            print(f"\n📋 Проверяю {log_name}...")

            # Получаем только новые записи (после сохраненной метки)
            if self.saved_logs_before.get(log_name):
                last_ts = self.saved_logs_before[log_name]['last_timestamp']

                # Ищем строки, которые появились после нашей метки
                command = f"""
                if [ -f {file_path} ]; then
                    awk '/{last_ts}/,0' {file_path} | tail -n +2
                fi
                """
            else:
                # Если файла не было, смотрим весь файл
                command = f"cat {file_path} 2>/dev/null"

            new_content = self.execute_command(command)

            if new_content:
                # Проверяем каждую строку на паттерны загрузки
                lines = new_content.splitlines()
                boot_lines = []

                for line in lines:
                    for pattern in self.boot_patterns[log_name]:
                        if re.search(pattern, line, re.IGNORECASE):
                            timestamp = self._extract_timestamp(line)

                            # Проверяем что запись в период отключения
                            if timestamp and power_off_time <= timestamp <= power_on_time:
                                boot_lines.append({
                                    'timestamp': timestamp.strftime('%H:%M:%S'),
                                    'line': line.strip()[:150]
                                })
                                break

                if boot_lines:
                    print(f"  ❌ НАЙДЕНЫ ПРИЗНАКИ ЗАГРУЗКИ В ПЕРИОД ОТКЛЮЧЕНИЯ:")
                    for bl in boot_lines:
                        print(f"     [{bl['timestamp']}] {bl['line'][:100]}")
                    violations.extend(boot_lines)
                else:
                    print(f"  ✅ Новых признаков загрузки в период отключения нет")
            else:
                print(f"  ✅ Нет новых записей")

        return violations

    def _extract_timestamp(self, log_line):
        """Извлечение временной метки из строки лога"""
        # Формат syslog: "Jul 13 10:30:45"
        syslog_pattern = r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
        match = re.search(syslog_pattern, log_line)

        if match:
            timestamp_str = match.group(1)
            try:
                current_year = datetime.now().year
                return datetime.strptime(
                    f"{current_year} {timestamp_str}",
                    "%Y %b %d %H:%M:%S"
                )
            except:
                pass

        return None


def wait_for_enter(message):
    """Ожидание нажатия Enter"""
    print(f"\n{'=' * 60}")
    print(message)
    print(f"{'=' * 60}")
    input("👉 Нажми ENTER когда будет готово...")
    return datetime.now()


def main():
    print("=" * 60)
    print("ТЕСТ: ПРОВЕРКА ИОНИСТОРОВ КОНТРОЛЛЕРА")
    print("Поиск паразитных загрузок при отключении питания")
    print("=" * 60)

    checker = ControllerBootChecker()

    # 1. Получаем параметры SSH
    checker.get_ssh_params()

    # 2. Подключаемся
    if not checker.connect_ssh():
        print("\n❌ Не удалось подключиться. Выход.")
        return

    # 3. Синхронизируем время
    input("\n📌 Синхронизируй время в конфигураторе и нажми ENTER...")
    checker.sync_time()

    # 4. Сохраняем логи ДО отключения
    checker.save_logs_before_poweroff()

    # 5. Отключаем питание
    print("\n" + "=" * 60)
    print("ОТКЛЮЧЕНИЕ ПИТАНИЯ")
    print("=" * 60)
    print("Сейчас нужно отключить контроллер от питания!")
    power_off_time = wait_for_enter("ОТКЛЮЧИ ПИТАНИЕ и нажми ENTER")
    print(f"✅ Время отключения: {power_off_time.strftime('%H:%M:%S')}")

    # 6. Отключаем SSH (контроллер все равно выключится)
    checker.disconnect_ssh()

    # 7. Ждем 3-5 минут
    print("\n" + "=" * 60)
    print("ОЖИДАНИЕ РАЗРЯДА ИОНИСТОРОВ")
    print("=" * 60)
    print("⏳ Жду 4 минуты пока разрядятся ионисторы...")
    print("   (в это время контроллер должен быть полностью выключен)")

    for i in range(4, 0, -1):
        print(f"   Осталось {i} мин...")
        time.sleep(60)

    # 8. Подаем питание
    print("\n" + "=" * 60)
    print("ПОДАЧА ПИТАНИЯ")
    print("=" * 60)
    power_on_time = wait_for_enter("ПОДАЙ ПИТАНИЕ и нажми ENTER")
    print(f"✅ Время включения: {power_on_time.strftime('%H:%M:%S')}")

    # 9. Ждем загрузки контроллера и подключаемся
    if not checker.wait_for_controller_and_reconnect():
        print("\n❌ Не удалось подключиться к контроллеру после включения")
        print("Возможно, логи можно проверить позже вручную.")
        return

    # 10. Проверяем логи на наличие паразитных загрузок
    violations = checker.check_new_logs(
        power_off_time - timedelta(seconds=5),
        power_on_time + timedelta(seconds=30)
    )

    # 11. Выводим итоги
    print("\n" + "=" * 60)
    print("ИТОГОВЫЙ РЕЗУЛЬТАТ")
    print("=" * 60)

    if not violations:
        print("✅ ТЕСТ ПРОЙДЕН!")
        print("В период отключения питания попыток загрузки НЕ обнаружено.")
        print("Ионисторы работают корректно - контроллер не пытался включиться.")
    else:
        print("❌ ТЕСТ НЕ ПРОЙДЕН!")
        print(f"Обнаружено {len(violations)} признаков загрузки в период отключения:")
        for v in violations:
            print(f"  • [{v['timestamp']}] {v['line']}")
        print("\n⚠️  Контроллер пытался загрузиться при отсутствии питания!")
        print("Необходимо проверить цепи ионисторов.")

    print("=" * 60)

    # Отключаемся
    checker.disconnect_ssh()
    print("\n💾 Логи также сохранены в файл 'logs_backup.txt'")


if __name__ == "__main__":
    try:
        import paramiko
    except ImportError:
        print("Устанавливаю paramiko...")
        os.system("pip install paramiko")
        import paramiko

    main()
    input("\nНажмите ENTER для выхода...")