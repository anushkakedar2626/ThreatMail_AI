import unittest

from app.demo_fixtures import match_demo_fixture


class DemoFixtureTests(unittest.TestCase):
    def test_final_four_fixtures(self):
        cases = [
            (
                "Scheduled Maintenance Notice",
                "This is a notice regarding scheduled internal system maintenance. Some internal services may be temporarily unavailable during this period. No action is required from employees at this time. Please contact the IT Operations team through the usual internal support channel.",
                "LOW",
            ),
            (
                "Invoice Review Reminder",
                "Our records indicate that an invoice is awaiting your immediate review. Please open the following link to review the invoice and confirm the payment details: http://login-verify-update.net/invoice. This action is required as soon as possible to avoid processing delays.",
                "SUSPICIOUS",
            ),
            (
                "Confidential: urgent gift card purchase",
                "I am in a meeting and need your help urgently. Purchase gift cards and send the codes to me as soon as possible. Do not call because I am unavailable. This is a synthetic executive-impersonation test email created for the ThreatMail AI demo.",
                "HIGH",
            ),
            (
                "Urgent: Verify your account within 24 hours",
                "We detected unusual activity on your account. Verify your identity immediately to avoid suspension. Verify here: https://login-verify-update.net/secure/confirm. This is a synthetic phishing test email created for the ThreatMail AI demo.",
                "CRITICAL",
            ),
        ]
        for subject, body, expected in cases:
            with self.subTest(subject=subject):
                fixture = match_demo_fixture(subject, body)
                self.assertIsNotNone(fixture)
                self.assertEqual(fixture.classification, expected)

    def test_unrelated_message_does_not_match(self):
        fixture = match_demo_fixture(
            "Invoice Review Reminder",
            "This is an unrelated message without the controlled invoice wording.",
        )
        self.assertIsNone(fixture)


class SyntheticLocationTests(unittest.TestCase):
    def test_all_six_synthetic_locations_are_detectable(self):
        from app.parser.ioc_extractor import find_earliest_reliable_public_ip
        from app.threat_intel.mock_provider import geolocate_ip

        expected = {
            "192.0.2.10": ("Mumbai", "India"),
            "192.0.2.20": ("Frankfurt", "Germany"),
            "192.0.2.30": ("Singapore", "Singapore"),
            "192.0.2.40": ("London", "United Kingdom"),
            "192.0.2.50": ("Sydney", "Australia"),
            "192.0.2.60": ("Pune", "India"),
        }

        for ip, (city, country) in expected.items():
            with self.subTest(ip=ip):
                result = find_earliest_reliable_public_ip([
                    f"Received: from demo (unknown [{ip}]) by mx.demo.example"
                ])
                self.assertEqual(result["ip"], ip)

                location = geolocate_ip(ip)
                self.assertTrue(location["demo_location"])
                self.assertEqual(location["city"], city)
                self.assertEqual(location["country"], country)
                self.assertTrue(location["synthetic_demo_data"])


if __name__ == "__main__":
    unittest.main()
