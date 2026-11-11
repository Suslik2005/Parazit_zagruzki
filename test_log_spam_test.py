import unittest

from log_spam_test import (
    ControllerSSH,
    LogResult,
    LogSpec,
    analyze_log,
    find_spam,
    normalize_message,
)


class CommandTests(unittest.TestCase):
    def test_root_executes_without_sudo(self):
        ssh = ControllerSSH("host", 22, "root", "secret")
        command, password = ssh.prepare_command("cat /var/log/syslog")
        self.assertEqual(command, "cat /var/log/syslog")
        self.assertIsNone(password)

    def test_root1_executes_every_command_with_sudo_and_password(self):
        ssh = ControllerSSH("host", 22, "root1", "secret")
        for original in ("cd /var/log && pwd", "cat /var/log/syslog", "stat /var/log/kern"):
            command, password = ssh.prepare_command(original)
            self.assertTrue(command.startswith("sudo -S -p '' bash -lc "))
            self.assertIn(original, command)
            self.assertEqual(password, "secret\n")


class SpamTests(unittest.TestCase):
    def test_burst_of_twenty_messages_is_spam(self):
        content = "\n".join(
            f"2026-11-11T13:00:{second:02d}.000 service[123]: connection failed"
            for second in range(20)
        )
        findings, _ = find_spam(content)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].max_burst, 20)

    def test_normal_messages_are_not_spam(self):
        content = "\n".join(
            f"2026-11-11T13:00:{second * 10:02d}.000 service[123]: connection failed"
            for second in range(5)
        )
        findings, _ = find_spam(content)
        self.assertEqual(findings, [])

    def test_hundred_repeats_are_spam_without_timestamps(self):
        findings, _ = find_spam("service: repeated error\n" * 100)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].count, 100)

    def test_old_timestamped_repeats_are_not_spam_by_total_count(self):
        lines = []
        for index in range(100):
            elapsed = index * 61
            hour = 13 + elapsed // 3600
            minute = (elapsed % 3600) // 60
            second = elapsed % 60
            lines.append(
                f"2026-11-11T{hour:02d}:{minute:02d}:{second:02d}.000 service: periodic message"
            )
        lines.extend(f"unique message {'x' * (index + 1)}" for index in range(900))
        findings, _ = find_spam("\n".join(lines))
        self.assertEqual(findings, [])

    def test_dominant_timestamped_repeats_are_spam(self):
        repeated = "2026-11-11T13:00:00.000 service: repeated warning\n" * 100
        other = "\n".join(f"unique {'x' * (index + 1)}" for index in range(400))
        findings, _ = find_spam(repeated + other)
        self.assertEqual(len(findings), 1)
        self.assertIn("файла", findings[0].reasons[0])

    def test_normalization_ignores_timestamp_pid_and_numbers(self):
        first = normalize_message("2026-11-11T13:00:00.000 service[123]: error 45 code 0x10")
        second = normalize_message("2026-11-11T13:00:01.000 service[456]: error 46 code 0x20")
        self.assertEqual(first, second)


class LogAnalysisTests(unittest.TestCase):
    def test_kernel_bug_is_failure(self):
        spec = LogSpec("kern", ("kern",))
        result = LogResult(
            "kern",
            content=(
                "2026-09-29T15:18:05.393 kernel:[ 62.363800] kernel BUG at lib/list_debug.c:56!\n"
                "2026-09-29T15:18:05.393 kernel:[ 62.363805] Internal error: Oops - BUG: 0 [#1] PREEMPT THUMB2"
            ),
        )
        analyze_log(spec, result)
        self.assertEqual(len(result.issues), 2)
        self.assertIn("kernel BUG", result.issues[0])

    def test_empty_optional_log_is_valid(self):
        result = LogResult("xprofibus", content="")
        analyze_log(LogSpec("xprofibus", ("xprofibus",)), result)
        self.assertEqual(result.issues, [])
        self.assertEqual(result.line_count, 0)

    def test_oversized_log_is_failure(self):
        result = LogResult("abakrt", content="normal line", size_bytes=101 * 1024 * 1024)
        analyze_log(LogSpec("abakrt", ("abakrt",)), result)
        self.assertTrue(any("превышает" in issue for issue in result.issues))


if __name__ == "__main__":
    unittest.main()
