import threading
import unittest
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from unittest.mock import patch

import app


BASE_CONFIG = {
    "host": "imap.gmail.com",
    "port": 993,
    "username": "user@gmail.com",
    "password": "app-password",
    "folder": "INBOX",
    "criteria": "ALL",
    "use_ssl": True,
}


def make_message():
    message = MIMEMultipart("mixed")
    alternative = MIMEMultipart("alternative")
    alternative.attach(MIMEText("plain", "plain", "utf-8"))
    alternative.attach(MIMEText("<b>html</b><script>alert(1)</script><img src=https://tracker.invalid/x>", "html", "utf-8"))
    message.attach(alternative)
    attachment = MIMEApplication(b"abc", "octet-stream")
    attachment.add_header("Content-Disposition", "attachment", filename="../safe.txt")
    message.attach(attachment)
    return message.as_bytes()


class FakeMail:
    def __init__(self, raw=None, select_status="OK", uids=None):
        self.raw = raw or b"Subject: Test\r\nFrom: sender@example.com\r\n\r\nBody"
        self.select_status = select_status
        self.uids = uids if uids is not None else [101, 205]
        self.calls = []

    def select(self, folder, readonly=False):
        self.calls.append(("select", folder, readonly))
        return self.select_status, [str(len(self.uids)).encode()]

    def list(self):
        self.calls.append(("list",))
        return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

    def response(self, code):
        if code == "UIDNEXT":
            return code, [str(max(self.uids, default=0) + 1).encode()]
        return code, None

    def uid(self, command, *args):
        self.calls.append(("uid", command, args))
        if command.lower() == "search":
            criteria = args[1:] if args and args[0] is None else args
            if criteria and criteria[0] == "UID":
                low, high = (int(value) for value in criteria[1].split(":"))
                return "OK", [" ".join(str(uid) for uid in self.uids if low <= uid <= high).encode()]
            return "OK", [" ".join(str(uid) for uid in self.uids).encode()]
        if command.lower() == "store":
            return "OK", [b""]
        if command.lower() != "fetch":
            raise AssertionError(command)
        uid_value = str(args[0])
        query = args[-1]
        if query == "(RFC822.SIZE)":
            return "OK", [(f"1 (UID {uid_value} RFC822.SIZE {len(self.raw)})".encode(), b"")]
        if str(query).startswith("(BODY.PEEK[]<0."):
            return "OK", [(f"1 (UID {uid_value} BODY[] {{{len(self.raw)}}})".encode(), self.raw)]
        rows = []
        for index, uid_value in enumerate(uid_value.split(","), 1):
            headers = (
                f"Subject: S{uid_value}\r\nFrom: sender@example.com\r\n"
                "To: user@gmail.com\r\nDate: Tue, 23 Sep 2026 10:00:00 +0000\r\n\r\n"
            ).encode()
            rows.append((f"{index} (UID {uid_value} FLAGS ())".encode(), headers))
        return "OK", rows

    def close(self):
        return None

    def logout(self):
        return None


class FakeSMTP:
    instances = []

    def __init__(self, *_args, **_kwargs):
        self.__class__.instances.append(self)
        self.quit_called = False

    def login(self, *_args):
        return None

    def sendmail(self, *_args):
        return {}

    def quit(self):
        self.quit_called = True


class AppSecurityTests(unittest.TestCase):
    def setUp(self):
        self.client = app.app.test_client()
        self.fake_mail = FakeMail(raw=make_message())
        self.session = {"client": self.fake_mail, "lock": threading.Lock(), "last_active": 0}
        self.imap_patch = patch.object(app, "get_imap_client", return_value=(self.session, ("test",)))
        self.invalidate_patch = patch.object(app, "invalidate_session")
        self.imap_patch.start()
        self.invalidate_patch.start()

    def tearDown(self):
        self.invalidate_patch.stop()
        self.imap_patch.stop()

    def post(self, path, payload):
        return self.client.post(
            path,
            json=payload,
            headers={"Host": "127.0.0.1:5000", "Origin": "http://127.0.0.1:5000"},
        )

    def test_uid_list_and_targeted_delete(self):
        response = self.post("/api/emails", {**BASE_CONFIG, "filter_bot_spam": False, "filter_delivery_status": False})
        self.assertEqual(response.status_code, 200)
        self.assertEqual([item["id"] for item in response.json["emails"]], ["205", "101"])
        searches = [call for call in self.fake_mail.calls if call[0] == "uid" and call[1] == "search"]
        self.assertTrue(searches)
        self.assertTrue(all("ALL" not in call[2] for call in searches))
        self.assertTrue(any("UID" in call[2] for call in searches))
        response = self.post("/api/email/205/delete", BASE_CONFIG)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(any(call[1] == "store" and call[2][0] == "205" for call in self.fake_mail.calls if call[0] == "uid"))
        self.assertFalse(any(call[0] == "expunge" for call in self.fake_mail.calls))

    def test_pagination_cursor_does_not_repeat_messages(self):
        response = self.post("/api/emails", {**BASE_CONFIG, "limit": 1, "page": 1, "filter_bot_spam": False, "filter_delivery_status": False})
        self.assertEqual(response.json["emails"][0]["id"], "205")
        self.assertTrue(response.json["has_more"])
        response = self.post("/api/emails", {**BASE_CONFIG, "limit": 1, "page": 2, "cursor": response.json["next_cursor"], "filter_bot_spam": False, "filter_delivery_status": False})
        self.assertEqual(response.json["emails"][0]["id"], "101")
        self.assertFalse(response.json["has_more"])

    def test_search_query_rejects_command_controls_and_accepts_utf8(self):
        response = self.post("/api/emails", {**BASE_CONFIG, "search_query": "主题"})
        self.assertEqual(response.status_code, 200)
        search_call = next(call for call in self.fake_mail.calls if call[0] == "uid" and call[1] == "search")
        self.assertIsInstance(search_call[2][-1], bytes)
        response = self.post("/api/emails", {**BASE_CONFIG, "search_query": "ok\r\nNOOP"})
        self.assertEqual(response.status_code, 400)

    def test_session_cleanup_unselects_without_close(self):
        class SessionClient:
            def __init__(self):
                self.calls = []

            def unselect(self):
                self.calls.append("unselect")

            def close(self):
                self.calls.append("close")

            def logout(self):
                self.calls.append("logout")

        client = SessionClient()
        app._close_session_client(client)
        self.assertEqual(client.calls, ["unselect", "logout"])

    def test_filtered_pagination_requires_cursor(self):
        response = self.post("/api/emails", {**BASE_CONFIG, "page": 2})
        self.assertEqual(response.status_code, 400)

    def test_large_mailbox_refresh_fetches_only_recent_uid_range(self):
        self.fake_mail.uids = list(range(1, 100_001))
        response = self.post(
            "/api/emails",
            {**BASE_CONFIG, "filter_bot_spam": False, "filter_delivery_status": False},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["emails"][0]["id"], "100000")
        searches = [call for call in self.fake_mail.calls if call[0] == "uid" and call[1] == "search"]
        fetches = [call for call in self.fake_mail.calls if call[0] == "uid" and call[1] == "fetch"]
        self.assertEqual(len(searches), 1)
        self.assertEqual(searches[0][2][-2:], ("UID", "99901:100000"))
        self.assertEqual(len(fetches), 1)
        self.assertEqual(len(fetches[0][2][0].split(",")), 100)

    def test_select_failure_blocks_read_and_delete(self):
        self.fake_mail.select_status = "NO"
        response = self.post("/api/email/101", BASE_CONFIG)
        self.assertEqual(response.status_code, 502)
        response = self.post("/api/email/101/delete", BASE_CONFIG)
        self.assertEqual(response.status_code, 502)
        self.assertFalse(any(call[1] == "store" for call in self.fake_mail.calls if call[0] == "uid"))

    def test_attachment_index_matches_detail(self):
        response = self.post("/api/email/101", BASE_CONFIG)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["email"]["attachments"][0]["index"], 0)
        response = self.post("/api/attachment", {**BASE_CONFIG, "msg_id": "101", "attachment_index": 0})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b"abc")

    def test_invalid_inputs_are_json_400(self):
        response = self.post("/api/emails", {**BASE_CONFIG, "limit": "nope"})
        self.assertEqual(response.status_code, 400)
        self.assertTrue(response.is_json)
        response = self.post("/api/email/1%0d%0aNOOP", BASE_CONFIG)
        self.assertEqual(response.status_code, 400)
        response = self.post("/api/emails", {**BASE_CONFIG, "folder": "INBOX\r\nNOOP"})
        self.assertEqual(response.status_code, 400)
        response = self.post("/api/emails", {**BASE_CONFIG, "cursor": {"unexpected": "object"}})
        self.assertEqual(response.status_code, 400)
        response = self.post("/api/emails", {**BASE_CONFIG, "page": 1.5})
        self.assertEqual(response.status_code, 400)

    def test_html_allowlist_and_security_headers(self):
        sanitized = app.sanitize_html('<script>alert(1)</script><a href="javascript:alert(1)">x</a><img src=https://tracker.invalid/x><p>ok</p>')
        self.assertNotIn("script", sanitized.lower())
        self.assertNotIn("javascript:", sanitized.lower())
        self.assertNotIn("tracker.invalid", sanitized)
        response = self.client.get("/", headers={"Host": "127.0.0.1:5000"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Content-Security-Policy", response.headers)
        self.assertIn("X-Frame-Options", response.headers)

    def test_smtp_partial_failure_is_not_success(self):
        class PartialSMTP(FakeSMTP):
            def sendmail(self, *_args):
                return {"bad@example.com": (550, b"rejected")}

        with patch.object(app.smtplib, "SMTP_SSL", PartialSMTP):
            response = self.post(
                "/api/send",
                {
                    "smtp_host": "smtp.gmail.com",
                    "smtp_port": 465,
                    "use_ssl": True,
                    "username": "user@gmail.com",
                    "password": "app-password",
                    "to": "good@example.com,bad@example.com",
                    "subject": "test",
                    "body": "body",
                },
            )
        self.assertEqual(response.status_code, 502)
        self.assertFalse(response.json["success"])
        self.assertTrue(PartialSMTP.instances[-1].quit_called)


if __name__ == "__main__":
    unittest.main()
