import unittest
from datetime import datetime

from ionistor_boot_test import (
    BootEvent,
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


if __name__ == "__main__":
    unittest.main()
