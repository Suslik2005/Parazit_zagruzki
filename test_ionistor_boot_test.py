import unittest
from datetime import datetime
from unittest.mock import Mock

from ionistor_boot_test import (
    BootEvent,
    ControllerSSH,
    classify_events,
    find_boot_events,
    parse_log_timestamp,
)


class TimestampTests(unittest.TestCase):
    def test_syslog_timestamp(self):
        reference = datetime(2026, 11, 2, 17, 0, 0)
        actual = parse_log_timestamp("Nov  2 16:30:15 controller kernel: test", reference)
        self.assertEqual(actual, datetime(2026, 11, 2, 16, 30, 15))

    def test_year_rollover(self):
        reference = datetime(2027, 1, 1, 0, 5, 0)
        actual = parse_log_timestamp("Dec 31 23:59:50 controller kernel: test", reference)
        self.assertEqual(actual, datetime(2026, 12, 31, 23, 59, 50))

    def test_iso_timestamp(self):
        reference = datetime(2026, 11, 2, 17, 0, 0)
        actual = parse_log_timestamp("2026-11-02T16:30:15.123456 controller test", reference)
        self.assertEqual(actual, datetime(2026, 11, 2, 16, 30, 15, 123456))

    def test_iso_timestamp_with_space(self):
        reference = datetime(2026, 11, 2, 17, 0, 0)
        actual = parse_log_timestamp("2026-11-02 16:30:15 controller test", reference)
        self.assertEqual(actual, datetime(2026, 11, 2, 16, 30, 15))


class ClassificationTests(unittest.TestCase):
    def setUp(self):
        self.power_off = datetime(2026, 11, 2, 16, 0, 0)
        self.power_on = datetime(2026, 11, 2, 16, 5, 0)
        self.current_boot = datetime(2026, 11, 2, 16, 5, 2)

    def event(self, timestamp):
        return BootEvent("kern.log", 1, "test", timestamp)

    def test_parasitic_boot_is_violation(self):
        events = [
            self.event(datetime(2026, 11, 2, 16, 2, 0)),
            self.event(self.current_boot),
        ]
        violations, current, undated = classify_events(
            events, self.power_off, self.power_on, self.current_boot
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(len(current), 1)
        self.assertEqual(undated, [])

    def test_current_boot_is_not_violation(self):
        events = [self.event(self.current_boot + self.current_boot.resolution)]
        violations, current, undated = classify_events(
            events, self.power_off, self.power_on, self.current_boot
        )
        self.assertEqual(violations, [])
        self.assertEqual(len(current), 1)

    def test_old_boot_is_not_violation(self):
        events = [self.event(datetime(2026, 11, 2, 15, 0, 0))]
        violations, current, undated = classify_events(
            events, self.power_off, self.power_on, self.current_boot
        )
        self.assertEqual(violations, [])
        self.assertEqual(current, [])

    def test_undated_event_requires_review(self):
        violations, current, undated = classify_events(
            [self.event(None)], self.power_off, self.power_on, self.current_boot
        )
        self.assertEqual(violations, [])
        self.assertEqual(len(undated), 1)


class PatternTests(unittest.TestCase):
    def test_expected_kernel_marker(self):
        logs = {
            "kern.log": "Nov  2 16:30:15 plc kernel:[    3.664212] Booting Linux on physical CPU 0x0000000000 [0x412fd050]"
        }
        events = find_boot_events(logs, datetime(2026, 11, 2, 17, 0, 0))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].timestamp, datetime(2026, 11, 2, 16, 30, 15))
        self.assertTrue(events[0].direct)

    def test_connmand_newlink_is_not_boot_evidence(self):
        logs = {
            "syslog": "2026-11-02T16:30:15.770 connmand[1074]: can0 {newlink} index 2 operstate 6 <UP>"
        }
        events = find_boot_events(logs, datetime(2026, 11, 2, 17, 0, 0))
        self.assertEqual(len(events), 1)
        self.assertFalse(events[0].direct)
        violations, current, undated = classify_events(
            events,
            datetime(2026, 11, 2, 16, 0, 0),
            datetime(2026, 11, 2, 16, 35, 0),
            datetime(2026, 11, 2, 16, 35, 2),
        )
        self.assertEqual(violations, [])
        self.assertEqual(current, [])
        self.assertEqual(undated, [])


class PermissionTests(unittest.TestCase):
    def setUp(self):
        self.ssh = ControllerSSH("192.168.1.100", 22, "root1", "secret")

    def test_password_sudo_is_used_after_permission_denied(self):
        self.ssh.execute = Mock(side_effect=[
            (1, "", "cat: /var/log/kern.log: Permission denied"),
            (1, "", "sudo: a password is required"),
            (0, "kernel log", ""),
        ])
        status, output, _ = self.ssh._read_file("/var/log/kern.log")
        self.assertEqual(status, 0)
        self.assertEqual(output, "kernel log")
        self.assertEqual(
            self.ssh.execute.call_args.kwargs["input_data"], "secret\n"
        )

    def test_missing_file_does_not_trigger_sudo(self):
        self.ssh.execute = Mock(return_value=(1, "", "No such file or directory"))
        status, _, _ = self.ssh._read_file("/var/log/missing.log")
        self.assertEqual(status, 1)
        self.ssh.execute.assert_called_once()


if __name__ == "__main__":
    unittest.main()
