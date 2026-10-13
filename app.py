import base64
import concurrent.futures
import ctypes
import hashlib
import html
import io
import imaplib
import json
import os
import re
import secrets
import smtplib
import ssl
import threading
import time
import uuid
from ctypes import wintypes
from datetime import datetime, timezone
from email import message_from_bytes
from email.header import Header, decode_header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, getaddresses
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, g, jsonify, render_template, request, send_file
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge


app = Flask(__name__)

MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_MESSAGE_BYTES = 12 * 1024 * 1024
MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024
MAX_BODY_CHARS = 750_000
MAX_HEADER_LENGTH = 998
MAX_LIST_LIMIT = 100
MAX_PAGE = 100_000
MAX_SEARCH_LENGTH = 500
MAX_FOLDER_LENGTH = 200
MAX_SESSION_COUNT = 8
SESSION_TTL_SECONDS = 180
IMAP_TIMEOUT_SECONDS = 20
SMTP_TIMEOUT_SECONDS = 20
MAX_RECENT_UID_SCAN = 20_000
UID_PATTERN = re.compile(r"^[1-9][0-9]{0,19}$")
HOST_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}[A-Za-z0-9]$|^[A-Za-z0-9]$")
EMAIL_PATTERN = re.compile(r"^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$")
CONTROL_PATTERN = re.compile(r"[\x00-\x1f\x7f]")

app.config["MAX_CONTENT_LENGTH"] = MAX_JSON_BYTES

_connection_lock = threading.Lock()
_active_sessions = {}
_profiles_lock = threading.RLock()

PROVIDERS = {
    "gmail": {"label": "Gmail", "domains": ["gmail.com", "googlemail.com"], "imap_host": "imap.gmail.com", "imap_port": 993, "imap_ssl": True, "smtp_host": "smtp.gmail.com", "smtp_port": 465, "smtp_ssl": True},
    "outlook": {"label": "Outlook / Hotmail", "domains": ["outlook.com", "hotmail.com", "live.com", "msn.com"], "imap_host": "outlook.office365.com", "imap_port": 993, "imap_ssl": True, "smtp_host": "smtp.office365.com", "smtp_port": 587, "smtp_ssl": False},
    "qq": {"label": "QQ 邮箱", "domains": ["qq.com"], "imap_host": "imap.qq.com", "imap_port": 993, "imap_ssl": True, "smtp_host": "smtp.qq.com", "smtp_port": 465, "smtp_ssl": True},
    "163": {"label": "网易 163", "domains": ["163.com"], "imap_host": "imap.163.com", "imap_port": 993, "imap_ssl": True, "smtp_host": "smtp.163.com", "smtp_port": 465, "smtp_ssl": True},
    "126": {"label": "网易 126", "domains": ["126.com"], "imap_host": "imap.126.com", "imap_port": 993, "imap_ssl": True, "smtp_host": "smtp.126.com", "smtp_port": 465, "smtp_ssl": True},
    "yeah": {"label": "网易 Yeah", "domains": ["yeah.net"], "imap_host": "imap.yeah.net", "imap_port": 993, "imap_ssl": True, "smtp_host": "smtp.yeah.net", "smtp_port": 465, "smtp_ssl": True},
    "yahoo": {"label": "Yahoo", "domains": ["yahoo.com", "yahoo.co.jp"], "imap_host": "imap.mail.yahoo.com", "imap_port": 993, "imap_ssl": True, "smtp_host": "smtp.mail.yahoo.com", "smtp_port": 465, "smtp_ssl": True},
    "icloud": {"label": "iCloud", "domains": ["icloud.com", "me.com", "mac.com"], "imap_host": "imap.mail.me.com", "imap_port": 993, "imap_ssl": True, "smtp_host": "smtp.mail.me.com", "smtp_port": 587, "smtp_ssl": False},
}


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _profile_store_path():
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        raise RuntimeError("Windows 本地用户数据目录不可用")
    return Path(local_app_data) / "GmailWebReader" / "accounts.json"


def _dpapi_transform(value, protect):
    if os.name != "nt":
        raise RuntimeError("预存邮箱密码仅支持 Windows DPAPI")
    source = ctypes.create_string_buffer(value)
    source_blob = _DataBlob(len(value), ctypes.cast(source, ctypes.POINTER(ctypes.c_byte)))
    result_blob = _DataBlob()
    if protect:
        ok = ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(source_blob), None, None, None, None, 0x1, ctypes.byref(result_blob)
        )
    else:
        ok = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(source_blob), None, None, None, None, 0x1, ctypes.byref(result_blob)
        )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(result_blob.pbData, result_blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(result_blob.pbData)


def _encrypt_password(password):
    encrypted = _dpapi_transform(password.encode("utf-8"), protect=True)
    return base64.b64encode(encrypted).decode("ascii")


def _decrypt_password(encoded):
    encrypted = base64.b64decode(encoded, validate=True)
    return _dpapi_transform(encrypted, protect=False).decode("utf-8")


def _read_profile_records():
    path = _profile_store_path()
    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("邮箱配置文件格式错误")
    return [record for record in payload if isinstance(record, dict) and record.get("id") and record.get("email")]


def _write_profile_records(records):
    path = _profile_store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(".tmp")
    temp_path.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temp_path, path)


def _provider_for_email(email):
    domain = email.rsplit("@", 1)[-1].lower()
    for provider_id, provider in PROVIDERS.items():
        if domain in provider["domains"]:
            return provider_id
    return None


def _ensure_profiles():
    with _profiles_lock:
        records = _read_profile_records()
        if records:
            return records
        import_file = Path(__file__).parent / "mail" / "Gmail IMAP.txt"
        if not import_file.exists():
            return []
        imported = []
        seen = set()
        for line in import_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not line.strip() or ":" not in line:
                continue
            email_address, password = line.split(":", 1)
            email_address = email_address.strip().lower()
            password = password.strip()
            provider_id = _provider_for_email(email_address)
            if email_address in seen or not provider_id or not EMAIL_PATTERN.fullmatch(email_address) or not password:
                continue
            seen.add(email_address)
            provider = PROVIDERS[provider_id]
            imported.append({
                "id": uuid.uuid4().hex,
                "email": email_address,
                "provider": provider_id,
                "password_enc": _encrypt_password(password),
                "status": "unchecked",
                "last_checked": None,
                "latency_ms": None,
                "error": None,
                "imap_host": provider["imap_host"],
                "imap_port": provider["imap_port"],
                "imap_ssl": provider["imap_ssl"],
                "smtp_host": provider["smtp_host"],
                "smtp_port": provider["smtp_port"],
                "smtp_ssl": provider["smtp_ssl"],
            })
        _write_profile_records(imported)
        return imported


def _public_profile(record):
    provider = PROVIDERS.get(record.get("provider"), {})
    return {
        "id": record["id"],
        "email": record["email"],
        "provider": record.get("provider", ""),
        "provider_label": provider.get("label", record.get("provider", "")),
        "imap_host": record.get("imap_host", ""),
        "imap_port": record.get("imap_port"),
        "status": record.get("status", "unchecked"),
        "last_checked": record.get("last_checked"),
        "latency_ms": record.get("latency_ms"),
        "error": record.get("error"),
    }


def _check_profile_record(record):
    started = time.monotonic()
    client = None
    try:
        password = _decrypt_password(record["password_enc"])
        client = create_imap_connection(
            record["imap_host"], record["imap_port"], record["email"], password, record["imap_ssl"]
        )
        status, _ = client.select("INBOX", readonly=True)
        if status != "OK":
            raise MailboxError("登录成功，但无法打开收件箱")
        result = {"status": "available", "error": None}
    except imaplib.IMAP4.error as error:
        detail = str(error).lower()
        if any(marker in detail for marker in ("auth", "credential", "password", "login")):
            result = {"status": "invalid", "error": "登录凭据被拒绝或需要应用专用密码"}
        else:
            result = {"status": "unavailable", "error": "IMAP 服务器拒绝连接"}
    except (TimeoutError, OSError, ssl.SSLError):
        result = {"status": "unavailable", "error": "连接超时或 TLS 握手失败"}
    except Exception:
        result = {"status": "unavailable", "error": "无法连接 IMAP 服务器"}
    finally:
        if client is not None:
            try:
                client.logout()
            except Exception:
                app.logger.debug("IMAP health-check logout failed", exc_info=True)
    result["latency_ms"] = round((time.monotonic() - started) * 1000)
    result["last_checked"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return result

DEFAULT_BOT_KEYWORDS = [
    "SUPERCHECKERBOT", "SUPERCHECKER", "SPVALIDCLOUD", "SPVALIDS", "SPVALID",
    "QUICKMAILCHECKER", "VIP PROTECTED",
]
DEFAULT_DELIVERY_KEYWORDS = [
    "DELIVERY STATUS NOTIFICATION", "MAIL DELIVERY SUBSYSTEM", "MAILER-DAEMON",
    "MESSAGE NON DISTRIBUÉ", "DELIVERY DELAY", "DELIVERY FAILURE",
]
DANGEROUS_EXTENSIONS = {
    "exe", "bat", "cmd", "scr", "pif", "vbs", "vbe", "js", "jse", "wsf", "wsh",
    "ps1", "ps1xml", "msi", "msp", "com", "hta", "cpl", "jar", "reg", "iso", "img",
    "vhd", "vhdx", "lnk", "sys", "dll",
}
SUSPICIOUS_EXTENSIONS = {
    "docm", "xlsm", "pptm", "dotm", "xltm", "zip", "rar", "7z", "tar", "gz", "cab", "ace",
}


class InputError(ValueError):
    pass


class MailboxError(RuntimeError):
    pass


class MessageTooLarge(RuntimeError):
    pass


def api_error(message, status):
    return jsonify({"success": False, "error": message}), status


def request_data():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise InputError("请求体必须是 JSON 对象")
    return data


def require_text(data, key, default=None, max_length=500, required=False):
    value = data.get(key, default)
    if value is None:
        if required:
            raise InputError(f"缺少参数: {key}")
        return default
    if not isinstance(value, str):
        raise InputError(f"参数 {key} 必须是字符串")
    value = value.strip()
    if len(value) > max_length or CONTROL_PATTERN.search(value):
        raise InputError(f"参数 {key} 无效或过长")
    if required and not value:
        raise InputError(f"参数 {key} 不能为空")
    return value


def require_body(data, key, default="", max_length=1_000_000):
    value = data.get(key, default)
    if not isinstance(value, str) or len(value) > max_length or "\x00" in value:
        raise InputError(f"参数 {key} 无效或过长")
    return value


def parse_int(data, key, default, minimum, maximum):
    value = data.get(key, default)
    if isinstance(value, bool):
        raise InputError(f"参数 {key} 必须是整数")
    if isinstance(value, float) and not value.is_integer():
        raise InputError(f"参数 {key} 必须是整数")
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise InputError(f"参数 {key} 必须是整数") from None
    if parsed < minimum or parsed > maximum:
        raise InputError(f"参数 {key} 超出允许范围")
    return parsed


def parse_bool(data, key, default=True):
    value = data.get(key, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in {"true", "false"}:
        return value.lower() == "true"
    raise InputError(f"参数 {key} 必须是布尔值")


def allowed_mail_hosts(environment_name, default):
    raw = os.environ.get(environment_name, default)
    return {item.strip().lower().rstrip(".") for item in raw.split(",") if item.strip()}


def validate_host(value, key, allowed_hosts):
    host = require_text({key: value}, key, max_length=253, required=True).lower().rstrip(".")
    if not HOST_PATTERN.fullmatch(host) or ".." in host:
        raise InputError(f"{key} 不是有效的服务器名称")
    if host not in allowed_hosts:
        raise InputError(f"{key} 不在允许的邮件服务器列表中")
    return host


def validate_email_address(value, key="邮箱"):
    if not EMAIL_PATTERN.fullmatch(value):
        raise InputError(f"{key} 格式无效")
    return value


def parse_imap_config(data):
    host = validate_host(
        data.get("host", "imap.gmail.com"),
        "IMAP 服务器",
        allowed_mail_hosts("GMAIL_WEB_ALLOWED_IMAP_HOSTS", "imap.gmail.com"),
    )
    port = parse_int(data, "port", 993, 1, 65535)
    username = require_text(data, "username", max_length=320, required=True)
    validate_email_address(username, "用户名")
    password = require_text(data, "password", max_length=256, required=True)
    folder = require_text(data, "folder", "INBOX", MAX_FOLDER_LENGTH, True)
    criteria = require_text(data, "criteria", "ALL", 32, True).upper()
    if criteria not in {"ALL", "UNSEEN"}:
        raise InputError("搜索范围只支持 ALL 或 UNSEEN")
    use_ssl = parse_bool(data, "use_ssl", True)
    if host == "imap.gmail.com" and (port != 993 or not use_ssl):
        raise InputError("Gmail IMAP 必须使用 993 端口和 SSL")
    return {
        "host": host, "port": port, "username": username, "password": password,
        "folder": folder, "criteria": criteria, "use_ssl": use_ssl,
    }


def parse_smtp_config(data):
    host = validate_host(
        data.get("smtp_host", "smtp.gmail.com"),
        "SMTP 服务器",
        allowed_mail_hosts("GMAIL_WEB_ALLOWED_SMTP_HOSTS", "smtp.gmail.com"),
    )
    port = parse_int(data, "smtp_port", 465, 1, 65535)
    username = require_text(data, "username", max_length=320, required=True)
    validate_email_address(username, "用户名")
    password = require_text(data, "password", max_length=256, required=True)
    use_ssl = parse_bool(data, "use_ssl", True)
    if host == "smtp.gmail.com" and not ((port == 465 and use_ssl) or (port == 587 and not use_ssl)):
        raise InputError("Gmail SMTP 必须使用 465/SSL 或 587/STARTTLS")
    return {"host": host, "port": port, "username": username, "password": password, "use_ssl": use_ssl}


def validate_uid(value, key="msg_id"):
    if not isinstance(value, str) or not UID_PATTERN.fullmatch(value):
        raise InputError(f"参数 {key} 必须是有效的邮件 UID")
    return value


def decode_str(header_value):
    if not header_value:
        return ""
    try:
        result = []
        for part, encoding in decode_header(header_value):
            if isinstance(part, bytes):
                result.append(part.decode(encoding or "utf-8", errors="replace"))
            else:
                result.append(str(part))
        return "".join(result).strip()
    except (LookupError, UnicodeError, ValueError):
        return str(header_value)


def is_bot_spam(subject, sender="", keywords=None):
    words = keywords if keywords is not None else DEFAULT_BOT_KEYWORDS
    return any(word in f"{subject} {sender}".upper() for word in words)


def is_delivery_notification(subject, sender="", keywords=None):
    words = keywords if keywords is not None else DEFAULT_DELIVERY_KEYWORDS
    return any(word in f"{subject} {sender}".upper() for word in words)


def classify_file_threat(filename):
    parts = filename.lower().split(".")
    if len(parts) < 2:
        return {"threat_level": "safe", "reason": ""}
    extension = parts[-1]
    if len(parts) >= 3 and extension in DANGEROUS_EXTENSIONS:
        return {"threat_level": "danger", "reason": f"双后缀伪装高危可执行文件 (.{parts[-2]}.{extension})"}
    if extension in DANGEROUS_EXTENSIONS:
        return {"threat_level": "danger", "reason": f"高危可执行文件/恶意脚本 (.{extension})"}
    if extension in SUSPICIOUS_EXTENSIONS:
        return {"threat_level": "warning", "reason": f"可携带宏代码或嵌入木马的载荷归档 (.{extension})"}
    return {"threat_level": "safe", "reason": ""}


def safe_filename(filename, fallback="attachment.bin"):
    value = decode_str(filename or "").replace("\\", "/")
    value = value.rsplit("/", 1)[-1]
    value = CONTROL_PATTERN.sub("", value).strip(" .")[:180]
    return value or fallback


def encode_imap_utf7(value):
    output = []
    buffer = []

    def flush():
        if buffer:
            encoded = base64.b64encode("".join(buffer).encode("utf-16-be")).decode("ascii")
            output.append("&" + encoded.rstrip("=").replace("/", ",") + "-")
            buffer.clear()

    for character in value:
        if "\x20" <= character <= "\x7e":
            flush()
            output.append("&-" if character == "&" else character)
        else:
            buffer.append(character)
    flush()
    return "".join(output)


def decode_imap_utf7(value):
    output = []
    position = 0
    while position < len(value):
        if value[position] != "&":
            output.append(value[position])
            position += 1
            continue
        end = value.find("-", position)
        if end < 0:
            output.append(value[position:])
            break
        token = value[position + 1:end]
        if not token:
            output.append("&")
        else:
            try:
                padded = token.replace(",", "/") + "=" * ((4 - len(token) % 4) % 4)
                output.append(base64.b64decode(padded).decode("utf-16-be", errors="replace"))
            except (ValueError, UnicodeError):
                output.append("�")
        position = end + 1
    return "".join(output)


def quoted_mailbox(folder):
    return quote_imap_arg(encode_imap_utf7(folder))


def quote_imap_arg(value):
    if not isinstance(value, str) or CONTROL_PATTERN.search(value):
        raise InputError("IMAP 参数包含非法控制字符")
    quoted = '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return quoted.encode("utf-8")


class SafeEmailHTMLParser(HTMLParser):
    allowed_tags = {
        "a", "b", "blockquote", "br", "code", "del", "div", "em", "h1", "h2", "h3",
        "h4", "h5", "h6", "hr", "i", "img", "li", "ol", "p", "pre", "s", "span",
        "strong", "table", "tbody", "td", "th", "thead", "tr", "u", "ul",
    }
    void_tags = {"br", "hr", "img"}
    blocked_container_tags = {"applet", "form", "iframe", "object", "script", "style", "svg", "template"}
    dropped_tags = {"base", "embed", "meta"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.output = []
        self.blocked_depth = 0

    @staticmethod
    def safe_uri(value, for_image=False):
        value = value.strip()
        if CONTROL_PATTERN.search(value):
            return ""
        scheme = urlsplit(value).scheme.lower()
        if for_image:
            if scheme == "cid" or (scheme == "data" and value.lower().startswith(("data:image/png", "data:image/jpeg", "data:image/gif", "data:image/webp"))):
                return value
            return ""
        if scheme in {"http", "https", "mailto"} or value.startswith("#"):
            return value
        return ""

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if self.blocked_depth:
            if tag in self.blocked_container_tags:
                self.blocked_depth += 1
            return
        if tag in self.dropped_tags:
            return
        if tag in self.blocked_container_tags:
            self.blocked_depth = 1
            return
        if tag not in self.allowed_tags:
            return
        safe_attrs = []
        for name, value in attrs:
            name = name.lower()
            if value is None:
                continue
            if name == "href" and tag == "a":
                safe_value = self.safe_uri(value)
                if safe_value:
                    safe_attrs.extend([("href", safe_value), ("rel", "noreferrer noopener"), ("target", "_blank")])
            elif name == "src" and tag == "img":
                safe_value = self.safe_uri(value, for_image=True)
                if safe_value:
                    safe_attrs.append(("src", safe_value))
            elif name in {"alt", "title", "colspan", "rowspan"} and tag in {"img", "td", "th"}:
                safe_attrs.append((name, value[:300]))
        attributes = "".join(f' {name}="{html.escape(value, quote=True)}"' for name, value in safe_attrs)
        self.output.append(f"<{tag}{attributes}>")

    def handle_startendtag(self, tag, attrs):
        if tag.lower() in self.blocked_container_tags | self.dropped_tags:
            return
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self.blocked_depth:
            if tag in self.blocked_container_tags:
                self.blocked_depth -= 1
            return
        if tag in self.allowed_tags and tag not in self.void_tags:
            self.output.append(f"</{tag}>")

    def handle_data(self, data):
        if not self.blocked_depth:
            self.output.append(html.escape(data))

    def handle_comment(self, _data):
        return


def sanitize_html(html_str):
    if not html_str:
        return ""
    parser = SafeEmailHTMLParser()
    try:
        parser.feed(html_str[:MAX_BODY_CHARS])
        parser.close()
    except (ValueError, AssertionError):
        return html.escape(html_str[:MAX_BODY_CHARS])
    return "".join(parser.output)


def _close_session_client(client):
    try:
        unselect = getattr(client, "unselect", None)
        if callable(unselect):
            unselect()
    except Exception:
        app.logger.debug("IMAP unselect failed", exc_info=True)
    try:
        client.logout()
    except Exception:
        app.logger.debug("IMAP logout failed", exc_info=True)


def _cleanup_sessions_locked(now=None):
    now = now or time.monotonic()
    stale_keys = [key for key, value in _active_sessions.items() if now - value["last_active"] >= SESSION_TTL_SECONDS]
    for key in stale_keys:
        session = _active_sessions.pop(key, None)
        if session:
            if session["lock"].acquire(blocking=False):
                try:
                    _close_session_client(session["client"])
                finally:
                    session["lock"].release()
            else:
                _active_sessions[key] = session
    while len(_active_sessions) > MAX_SESSION_COUNT:
        removed = False
        for oldest_key in sorted(_active_sessions, key=lambda key: _active_sessions[key]["last_active"]):
            session = _active_sessions[oldest_key]
            if not session["lock"].acquire(blocking=False):
                continue
            try:
                _active_sessions.pop(oldest_key, None)
                _close_session_client(session["client"])
                removed = True
                break
            finally:
                session["lock"].release()
        if not removed:
            break


def create_imap_connection(host, port, username, password, use_ssl=True):
    if use_ssl:
        client = imaplib.IMAP4_SSL(host, port, ssl_context=ssl.create_default_context(), timeout=IMAP_TIMEOUT_SECONDS)
    else:
        client = imaplib.IMAP4(host, port, timeout=IMAP_TIMEOUT_SECONDS)
        status, _ = client.starttls(ssl_context=ssl.create_default_context())
        if status != "OK":
            _close_session_client(client)
            raise imaplib.IMAP4.error("IMAP STARTTLS failed")
    try:
        client.login(username, password)
        try:
            client.enable("UTF8=ACCEPT")
        except (AttributeError, imaplib.IMAP4.error):
            app.logger.debug("IMAP UTF8=ACCEPT is unavailable")
    except Exception:
        _close_session_client(client)
        raise
    return client


def get_imap_client(host, port, username, password, use_ssl=True, **_unused):
    password_digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
    key = (host, int(port), username, password_digest, bool(use_ssl))
    now = time.monotonic()
    with _connection_lock:
        _cleanup_sessions_locked(now)
        session = _active_sessions.get(key)
        if session:
            session["last_active"] = now
            return session, key
        client = create_imap_connection(host, port, username, password, use_ssl)
        session = {"client": client, "last_active": now, "lock": threading.Lock()}
        _active_sessions[key] = session
        _cleanup_sessions_locked(now)
        return session, key


def invalidate_session(key):
    with _connection_lock:
        session = _active_sessions.pop(key, None)
    if session:
        with session["lock"]:
            _close_session_client(session["client"])


def select_mailbox(mail, folder, readonly=False):
    status, data = mail.select(quoted_mailbox(folder), readonly=readonly)
    if status != "OK":
        raise MailboxError("无法打开指定邮箱目录")
    try:
        return int((data or [b"0"])[0] or b"0")
    except (TypeError, ValueError):
        return 0


def selected_uidnext(mail):
    try:
        _kind, values = mail.response("UIDNEXT")
    except (AttributeError, imaplib.IMAP4.error):
        values = None
    for value in values or []:
        match = re.search(rb"\d+", value if isinstance(value, bytes) else str(value).encode("ascii", errors="ignore"))
        if match:
            return int(match.group())
    # Older servers may omit UIDNEXT from SELECT; retain compatibility as a slow fallback.
    uids = uid_search(mail, "ALL")
    return int(uids[-1]) + 1 if uids else 1


def uid_search(mail, *criteria):
    status, data = mail.uid("search", None, *criteria)
    if status != "OK":
        raise MailboxError("邮箱搜索失败")
    raw = data[0] if data else b""
    if isinstance(raw, str):
        raw = raw.encode("ascii", errors="ignore")
    result = []
    for token in raw.split():
        value = token.decode("ascii", errors="ignore")
        if UID_PATTERN.fullmatch(value):
            result.append(value)
    return sorted(set(result), key=int)


def parse_uid_from_metadata(metadata):
    if isinstance(metadata, bytes):
        metadata = metadata.decode("ascii", errors="ignore")
    match = re.search(r"\bUID\s+([0-9]+)", metadata or "", re.IGNORECASE)
    if not match:
        return None
    value = match.group(1)
    return value if UID_PATTERN.fullmatch(value) else None


def fetch_header_map(mail, uids):
    if not uids:
        return {}
    status, fetched = mail.uid("fetch", ",".join(uids), "(UID BODY.PEEK[HEADER.FIELDS (SUBJECT FROM TO DATE)] FLAGS)")
    if status != "OK":
        raise MailboxError("读取邮件列表失败")
    results = {}
    for item in fetched or []:
        if not isinstance(item, tuple) or len(item) < 2 or not isinstance(item[1], bytes):
            continue
        uid = parse_uid_from_metadata(item[0])
        if not uid:
            continue
        metadata = item[0].decode("ascii", errors="ignore") if isinstance(item[0], bytes) else str(item[0])
        flags_match = re.search(r"FLAGS\s*\(([^)]*)\)", metadata, re.IGNORECASE)
        flags = flags_match.group(1) if flags_match else ""
        parsed = message_from_bytes(item[1])
        results[uid] = {
            "id": uid,
            "subject": decode_str(parsed.get("Subject", "(无主题)")),
            "from": decode_str(parsed.get("From", "(未知发件人)")),
            "to": decode_str(parsed.get("To", "")),
            "date": parsed.get("Date", ""),
            "is_unread": "\\Seen" not in flags,
        }
    return results


def collect_page(mail, uids, page, limit, cursor, filter_bot, filter_delivery):
    total = len(uids)
    if not filter_bot and not filter_delivery:
        scan_end = cursor if cursor else max(0, total - (page - 1) * limit)
        scan_end = min(max(scan_end, 0), total)
        start = max(0, scan_end - limit)
        page_uids = uids[start:scan_end]
        item_map = fetch_header_map(mail, page_uids)
        items = [item_map[uid] for uid in reversed(page_uids) if uid in item_map]
        return items, start or None, 0

    scan_end = cursor if cursor else total
    scan_end = min(max(scan_end, 0), total)
    collected = []
    blocked_count = 0
    scanned = 0
    while scan_end > 0 and len(collected) < limit and scanned < 20_000:
        start = max(0, scan_end - 500)
        batch_uids = uids[start:scan_end]
        item_map = fetch_header_map(mail, batch_uids)
        exhausted_batch = True
        for offset, uid in enumerate(reversed(batch_uids)):
            item = item_map.get(uid)
            if not item:
                continue
            blocked = (filter_bot and is_bot_spam(item["subject"], item["from"])) or (filter_delivery and is_delivery_notification(item["subject"], item["from"]))
            if blocked:
                blocked_count += 1
                continue
            collected.append(item)
            if len(collected) >= limit:
                scan_end = scan_end - offset - 1
                exhausted_batch = False
                break
        if exhausted_batch:
            scan_end = start
        scanned += len(batch_uids)
    return collected, scan_end or None, blocked_count


def collect_recent_page(mail, uidnext, total, page, limit, cursor, filter_bot, filter_delivery):
    upper = min(cursor if cursor else uidnext - 1, uidnext - 1)
    width = max(100, limit * 5)
    scanned_uids = 0
    blocked_count = 0
    collected = []
    has_unprocessed_uids = False

    while upper > 0 and scanned_uids < MAX_RECENT_UID_SCAN and len(collected) < limit:
        lower = max(1, upper - width + 1)
        uids = uid_search(mail, "UID", f"{lower}:{upper}")
        item_map = fetch_header_map(mail, uids)
        processed = 0
        exhausted_range = True

        for uid in reversed(uids):
            processed += 1
            item = item_map.get(uid)
            if not item:
                continue
            blocked = (filter_bot and is_bot_spam(item["subject"], item["from"])) or (
                filter_delivery and is_delivery_notification(item["subject"], item["from"])
            )
            if blocked:
                blocked_count += 1
                continue
            collected.append(item)
            if len(collected) >= limit:
                upper = int(uid) - 1
                has_unprocessed_uids = any(int(candidate) <= upper for candidate in uids)
                exhausted_range = False
                break

        scanned_uids += processed if not exhausted_range else len(uids)
        if exhausted_range:
            upper = lower - 1
            width = min(width * 2, 4000)

    next_cursor = upper or None
    if not next_cursor:
        has_more = False
    elif has_unprocessed_uids or (page == 1 and scanned_uids < total):
        has_more = True
    else:
        probe_high = next_cursor
        probe_width = 100
        has_more = False
        while probe_high > 0:
            probe_low = max(1, probe_high - probe_width + 1)
            if uid_search(mail, "UID", f"{probe_low}:{probe_high}"):
                has_more = True
                break
            probe_high = probe_low - 1
            probe_width = min(probe_width * 2, 4000)
    return collected, next_cursor, blocked_count, has_more


def extract_message_bytes(fetched):
    for item in fetched or []:
        if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], bytes):
            return item[1]
    return None


def fetch_full_message(mail, uid):
    status, size_data = mail.uid("fetch", uid, "(RFC822.SIZE)")
    if status != "OK":
        raise MailboxError("无法读取邮件大小")
    size = None
    for item in size_data or []:
        metadata = item[0] if isinstance(item, tuple) else item
        if isinstance(metadata, bytes):
            metadata = metadata.decode("ascii", errors="ignore")
        match = re.search(r"RFC822\.SIZE\s+(\d+)", str(metadata), re.IGNORECASE)
        if match:
            size = int(match.group(1))
            break
    if size is not None and size > MAX_MESSAGE_BYTES:
        raise MessageTooLarge("邮件超过允许的大小限制")
    status, fetched = mail.uid("fetch", uid, f"(BODY.PEEK[]<0.{MAX_MESSAGE_BYTES + 1}>)")
    if status != "OK":
        raise MailboxError("无法读取邮件内容")
    raw_bytes = extract_message_bytes(fetched)
    if raw_bytes is None:
        raise MailboxError("未找到指定邮件")
    if len(raw_bytes) > MAX_MESSAGE_BYTES:
        raise MessageTooLarge("邮件超过允许的大小限制")
    return raw_bytes


def decode_part_text(part):
    payload = part.get_payload(decode=True)
    if not payload:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")[:MAX_BODY_CHARS]
    except (LookupError, UnicodeError):
        return payload.decode("utf-8", errors="replace")[:MAX_BODY_CHARS]


def parse_email(raw_bytes, uid):
    message = message_from_bytes(raw_bytes)
    subject = decode_str(message.get("Subject", "(无主题)"))
    sender = decode_str(message.get("From", "(未知发件人)"))
    body_text = ""
    body_html = ""
    attachments = []
    parts = message.walk() if message.is_multipart() else [message]
    for part in parts:
        content_type = part.get_content_type()
        disposition = str(part.get("Content-Disposition", "")).lower()
        filename = part.get_filename()
        if "attachment" in disposition or filename:
            payload = part.get_payload(decode=True) or b""
            safe_name = safe_filename(filename, f"attachment_{len(attachments)}.bin")
            threat = classify_file_threat(safe_name)
            attachments.append({
                "index": len(attachments), "filename": safe_name, "content_type": content_type,
                "size": len(payload), "threat_level": threat["threat_level"], "threat_reason": threat["reason"],
            })
            continue
        if content_type == "text/plain" and not body_text:
            body_text = decode_part_text(part)
        elif content_type == "text/html" and not body_html:
            body_html = decode_part_text(part)
    return {
        "id": uid, "subject": subject, "from": sender, "to": decode_str(message.get("To", "")),
        "cc": decode_str(message.get("Cc", "")), "date": message.get("Date", ""),
        "body_text": body_text, "body_html": sanitize_html(body_html), "attachments": attachments,
        "is_bot_spam": is_bot_spam(subject, sender) or is_bot_spam(body_text[:200]),
        "is_delivery_notification": is_delivery_notification(subject, sender),
    }


def parse_folders(folder_list):
    folders = []
    for item in folder_list or []:
        if not isinstance(item, bytes):
            continue
        line = item.decode("ascii", errors="replace")
        match = re.search(r'(?:(?:^|\s)"((?:[^"\\]|\\.)*)"|(?:^|\s)([^\s]+))\s*$', line)
        if not match:
            continue
        mailbox = match.group(1) if match.group(1) is not None else match.group(2)
        mailbox = mailbox.replace('\\"', '"').replace("\\\\", "\\")
        folders.append(decode_imap_utf7(mailbox))
    return folders


def parse_recipients(value, key):
    value = require_text({key: value}, key, max_length=4000, required=True)
    addresses = getaddresses([value])
    if not addresses or len(addresses) > 100:
        raise InputError(f"{key} 收件人数量无效")
    result = []
    for _display_name, address in addresses:
        if not EMAIL_PATTERN.fullmatch(address):
            raise InputError(f"{key} 中包含无效邮箱地址")
        result.append(address)
    return result


@app.before_request
def enforce_local_web_origin():
    g.csp_nonce = secrets.token_urlsafe(18)
    try:
        host = (urlsplit(f"http://{request.host}").hostname or "").lower()
    except ValueError:
        host = ""
    if host not in {"127.0.0.1", "localhost", "::1"}:
        return api_error("仅允许本机访问", 403) if request.path.startswith("/api/") else ("Forbidden", 403)
    origin = request.headers.get("Origin")
    if origin:
        try:
            if origin.rstrip("/") != request.host_url.rstrip("/"):
                return api_error("跨站请求被拒绝", 403) if request.path.startswith("/api/") else ("Forbidden", 403)
        except ValueError:
            return api_error("跨站请求被拒绝", 403) if request.path.startswith("/api/") else ("Forbidden", 403)
    if request.headers.get("Sec-Fetch-Site", "").lower() == "cross-site":
        return api_error("跨站请求被拒绝", 403) if request.path.startswith("/api/") else ("Forbidden", 403)
    return None


@app.after_request
def add_security_headers(response):
    nonce = getattr(g, "csp_nonce", "")
    response.headers.setdefault("Content-Security-Policy", f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data: cid:; font-src 'self' data:; connect-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    if request.path.startswith("/api/") or request.path == "/":
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.errorhandler(RequestEntityTooLarge)
def request_too_large(_error):
    return api_error("请求体超过大小限制", 413)


@app.errorhandler(Exception)
def handle_unexpected_error(error):
    if isinstance(error, HTTPException):
        if request.path.startswith("/api/"):
            message = "请求的 API 不存在" if error.code == 404 else "请求方法或参数无效"
            return api_error(message, error.code or 400)
        return error
    app.logger.exception("Unhandled request error: %s", error)
    if request.path.startswith("/api/"):
        return api_error("服务器内部错误", 500)
    return "服务器内部错误", 500


@app.route("/")
def index():
    return render_template("index.html", csp_nonce=g.csp_nonce)


@app.route("/api/folders", methods=["POST"])
def list_folders():
    session_key = None
    try:
        config = parse_imap_config(request_data())
        session, session_key = get_imap_client(**config)
        with session["lock"]:
            status, folder_list = session["client"].list()
            if status != "OK":
                raise MailboxError("无法读取邮箱目录")
            folders = parse_folders(folder_list)
        return jsonify({"success": True, "folders": folders})
    except InputError as error:
        return api_error(str(error), 400)
    except imaplib.IMAP4.error as error:
        if session_key:
            invalidate_session(session_key)
        app.logger.info("IMAP folder error: %s", error)
        return api_error("IMAP 认证或连接失败", 401)
    except MailboxError as error:
        if session_key:
            invalidate_session(session_key)
        return api_error(str(error), 502)
    except Exception:
        if session_key:
            invalidate_session(session_key)
        app.logger.exception("Folder listing failed")
        return api_error("连接邮箱失败", 502)


@app.route("/api/emails", methods=["POST"])
def list_emails():
    session_key = None
    try:
        data = request_data()
        config = parse_imap_config(data)
        limit = parse_int(data, "limit", 20, 1, MAX_LIST_LIMIT)
        page = parse_int(data, "page", 1, 1, MAX_PAGE)
        cursor_value = data.get("cursor", 0)
        cursor = 0 if cursor_value in (None, "") else parse_int(data, "cursor", 0, 0, 10_000_000_000_000_000_000)
        search_query = require_text(data, "search_query", "", MAX_SEARCH_LENGTH)
        filter_bot = parse_bool(data, "filter_bot_spam", True)
        filter_delivery = parse_bool(data, "filter_delivery_status", True)
        cursor_required = (not search_query and config["criteria"] == "ALL") or filter_bot or filter_delivery
        if page > 1 and cursor_required and not cursor:
            raise InputError("后续页面需要使用上一页返回的游标")
        session, session_key = get_imap_client(**config)
        with session["lock"]:
            mail = session["client"]
            total_in_folder = select_mailbox(mail, config["folder"], readonly=True)
            if not search_query and config["criteria"] == "ALL":
                emails, next_cursor, blocked_count, has_more = collect_recent_page(
                    mail,
                    selected_uidnext(mail),
                    total_in_folder,
                    page,
                    limit,
                    cursor,
                    filter_bot,
                    filter_delivery,
                )
                result_total = total_in_folder
            else:
                if search_query:
                    search_done = False
                    if config["host"] == "imap.gmail.com":
                        try:
                            uids = uid_search(mail, "X-GM-RAW", quote_imap_arg(search_query))
                            search_done = True
                        except (MailboxError, imaplib.IMAP4.error, UnicodeError):
                            search_done = False
                    if not search_done:
                        uids = uid_search(mail, "CHARSET", "UTF-8", "TEXT", quote_imap_arg(search_query))
                else:
                    uids = uid_search(mail, config["criteria"])
                emails, next_cursor, blocked_count = collect_page(mail, uids, page, limit, cursor, filter_bot, filter_delivery)
                result_total = len(uids)
                has_more = next_cursor is not None
        return jsonify({
            "success": True, "total": result_total, "total_in_folder": total_in_folder, "page": page,
            "limit": limit, "next_cursor": next_cursor, "has_more": has_more,
            "blocked_spam_count": blocked_count, "emails": emails,
        })
    except InputError as error:
        return api_error(str(error), 400)
    except MessageTooLarge as error:
        return api_error(str(error), 413)
    except imaplib.IMAP4.error as error:
        if session_key:
            invalidate_session(session_key)
        app.logger.info("IMAP list error: %s", error)
        return api_error("IMAP 认证或连接失败", 401)
    except MailboxError as error:
        if session_key:
            invalidate_session(session_key)
        return api_error(str(error), 502)
    except Exception:
        if session_key:
            invalidate_session(session_key)
        app.logger.exception("Email list failed")
        return api_error("加载邮件列表失败", 502)


@app.route("/api/email/<msg_id>", methods=["POST"])
def get_email_detail(msg_id):
    session_key = None
    try:
        uid = validate_uid(msg_id)
        config = parse_imap_config(request_data())
        session, session_key = get_imap_client(**config)
        with session["lock"]:
            mail = session["client"]
            select_mailbox(mail, config["folder"], readonly=True)
            raw_bytes = fetch_full_message(mail, uid)
        return jsonify({"success": True, "email": parse_email(raw_bytes, uid)})
    except InputError as error:
        return api_error(str(error), 400)
    except MessageTooLarge as error:
        return api_error(str(error), 413)
    except MailboxError as error:
        if session_key:
            invalidate_session(session_key)
        return api_error(str(error), 404 if "找不到" in str(error) else 502)
    except imaplib.IMAP4.error as error:
        if session_key:
            invalidate_session(session_key)
        app.logger.info("IMAP detail error: %s", error)
        return api_error("读取邮件失败", 502)
    except Exception:
        if session_key:
            invalidate_session(session_key)
        app.logger.exception("Email detail failed")
        return api_error("读取邮件详情失败", 502)


@app.route("/api/email/<msg_id>/delete", methods=["POST"])
def delete_email(msg_id):
    session_key = None
    try:
        uid = validate_uid(msg_id)
        config = parse_imap_config(request_data())
        session, session_key = get_imap_client(**config)
        with session["lock"]:
            mail = session["client"]
            select_mailbox(mail, config["folder"], readonly=False)
            status, _ = mail.uid("store", uid, "+FLAGS.SILENT", "(\\Deleted)")
            if status != "OK":
                raise MailboxError("标记邮件删除失败")
        return jsonify({"success": True, "message": f"邮件 #{uid} 已标记删除", "id": uid})
    except InputError as error:
        return api_error(str(error), 400)
    except MailboxError as error:
        if session_key:
            invalidate_session(session_key)
        return api_error(str(error), 502)
    except imaplib.IMAP4.error as error:
        if session_key:
            invalidate_session(session_key)
        app.logger.info("IMAP delete error: %s", error)
        return api_error("删除邮件失败", 502)
    except Exception:
        if session_key:
            invalidate_session(session_key)
        app.logger.exception("Email delete failed")
        return api_error("删除邮件失败", 502)


@app.route("/api/attachment", methods=["POST"])
def download_attachment():
    session_key = None
    try:
        data = request_data()
        config = parse_imap_config(data)
        uid = validate_uid(data.get("msg_id"))
        target_index = parse_int(data, "attachment_index", -1, 0, 1000)
        session, session_key = get_imap_client(**config)
        with session["lock"]:
            mail = session["client"]
            select_mailbox(mail, config["folder"], readonly=True)
            raw_bytes = fetch_full_message(mail, uid)
        message = message_from_bytes(raw_bytes)
        attachment_index = 0
        for part in message.walk() if message.is_multipart() else [message]:
            disposition = str(part.get("Content-Disposition", "")).lower()
            if "attachment" not in disposition and not part.get_filename():
                continue
            if attachment_index == target_index:
                payload = part.get_payload(decode=True) or b""
                if len(payload) > MAX_ATTACHMENT_BYTES:
                    raise MessageTooLarge("附件超过允许的大小限制")
                filename = safe_filename(part.get_filename(), f"attachment_{attachment_index}.bin")
                threat = classify_file_threat(filename)
                response = send_file(
                    io.BytesIO(payload),
                    mimetype="application/octet-stream" if threat["threat_level"] == "danger" else (part.get_content_type() or "application/octet-stream"),
                    as_attachment=True,
                    download_name=filename,
                    max_age=0,
                )
                response.headers["Content-Security-Policy"] = "default-src 'none'"
                response.headers["Cache-Control"] = "no-store"
                return response
            attachment_index += 1
        return api_error("未找到对应的附件", 404)
    except InputError as error:
        return api_error(str(error), 400)
    except MessageTooLarge as error:
        return api_error(str(error), 413)
    except MailboxError as error:
        if session_key:
            invalidate_session(session_key)
        return api_error(str(error), 404 if "找不到" in str(error) else 502)
    except imaplib.IMAP4.error as error:
        if session_key:
            invalidate_session(session_key)
        app.logger.info("IMAP attachment error: %s", error)
        return api_error("下载附件失败", 502)
    except Exception:
        if session_key:
            invalidate_session(session_key)
        app.logger.exception("Attachment download failed")
        return api_error("下载附件失败", 502)


@app.route("/api/send", methods=["POST"])
def send_email():
    server = None
    try:
        data = request_data()
        config = parse_smtp_config(data)
        to_addresses = parse_recipients(data.get("to", ""), "收件人")
        cc_value = require_text(data, "cc", "", 4000)
        cc_addresses = parse_recipients(cc_value, "抄送") if cc_value else []
        subject = require_text(data, "subject", "(无主题)", MAX_HEADER_LENGTH)
        body = require_body(data, "body", "", 1_000_000)
        is_html = parse_bool(data, "is_html", False)
        message = MIMEMultipart("alternative")
        display_name = config["username"].split("@", 1)[0][:80]
        message["From"] = formataddr((Header(display_name, "utf-8").encode(), config["username"]))
        message["To"] = ", ".join(to_addresses)
        if cc_addresses:
            message["Cc"] = ", ".join(cc_addresses)
        message["Subject"] = Header(subject, "utf-8")
        message.attach(MIMEText(body, "html" if is_html else "plain", "utf-8"))

        if config["use_ssl"] or config["port"] == 465:
            server = smtplib.SMTP_SSL(config["host"], config["port"], timeout=SMTP_TIMEOUT_SECONDS, context=ssl.create_default_context())
        else:
            server = smtplib.SMTP(config["host"], config["port"], timeout=SMTP_TIMEOUT_SECONDS)
            server.ehlo()
            status, _ = server.starttls(context=ssl.create_default_context())
            if status != 220:
                raise smtplib.SMTPException("SMTP STARTTLS failed")
            server.ehlo()
        server.login(config["username"], config["password"])
        failures = server.sendmail(config["username"], to_addresses + cc_addresses, message.as_string())
        if failures:
            failed_addresses = ", ".join(sorted(failures.keys())[:20])
            return api_error(f"部分收件人发送失败: {failed_addresses}", 502)
        return jsonify({"success": True, "message": "邮件发送成功"})
    except InputError as error:
        return api_error(str(error), 400)
    except smtplib.SMTPAuthenticationError:
        return api_error("SMTP 认证失败，请检查账号和应用专用密码", 401)
    except Exception:
        app.logger.exception("SMTP send failed")
        return api_error("发送邮件失败", 502)
    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                app.logger.debug("SMTP quit failed", exc_info=True)


if __name__ == "__main__":
    print("=" * 60)
    print("Gmail IMAP & SMTP Web 客户端")
    print("请在浏览器中打开: http://127.0.0.1:5000")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
