import datetime
import gzip
import json
import re
import uuid
from email.header import decode_header, make_header
from email.parser import BytesParser
from email.policy import compat32
from email.utils import getaddresses, parsedate, parsedate_to_datetime
from io import BytesIO

from email_validator import validate_email
from html2text import html2text

from extract_raw_content.html import strip_email_quote
from extract_raw_content.text import (
    exctract_quoted_from_plain,
    extract_non_quoted_from_plain,
)

JSON_MIME = "application/json"
GZ_MIME = "application/gzip"
EML_MIME = "message/rfc822"
BINARY_MIME = "application/octet-stream"
_BASIC_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+$")  # intentionally permissive


def validate_and_normalize(addr: str) -> str | None:
    if not addr:
        return None
    addr = addr.strip().strip("<>").strip().strip('"').strip("'")

    # First try strict/standard validation
    try:
        v = validate_email(addr, check_deliverability=False)
        return v.normalized.lower()
    except Exception:
        # Fallback: accept internal domains if they look like an email
        if _BASIC_EMAIL_RE.match(addr):
            return addr.lower()
        return None


def _coerce_addresses(source):
    """
    Normalize various address shapes into list[tuple(display_name, email)].
    Supports:
      - list/tuple/set of (name, email)
      - string headers: "Name <a@b>", "a@b, c@d"
      - dicts: {"email": ...} / {"address": ...} / {"name": ..., "email": ...}
      - list of dicts (common in some parsers)
    """
    if not source:
        return []

    # Already in [(name, email), ...] form
    if isinstance(source, (list, tuple, set)):
        src_list = list(source)
        if (
            src_list
            and isinstance(src_list[0], (list, tuple))
            and len(src_list[0]) >= 2
        ):
            return [(x[0], x[1]) for x in src_list if x and len(x) >= 2]
        # list of dicts
        if src_list and isinstance(src_list[0], dict):
            out = []
            for d in src_list:
                if not d:
                    continue
                email = d.get("email") or d.get("address")
                name = d.get("name") or d.get("display_name") or ""
                if email:
                    out.append((name, email))
            return out

    # Single dict
    if isinstance(source, dict):
        email = source.get("email") or source.get("address")
        name = source.get("name") or source.get("display_name") or ""
        return [(name, email)] if email else []

    # Raw header string
    if isinstance(source, str):
        return getaddresses([source])

    return []


def extract_emails(source):
    pairs = _coerce_addresses(source)
    normalized = [validate_and_normalize(email) for _, email in pairs if email]
    return [x for x in normalized if x]


def _str_header(value) -> str:
    """Decode an RFC2047 encoded header value to a plain Unicode string."""
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _addr_list(msg, name: str):
    """Return list of (display_name, email) tuples for an address header."""
    return getaddresses(msg.get_all(name) or [])


def _parse_received(raw: str) -> dict:
    """Extract address from the 'for' clause; keep full text as 'others' fallback."""
    result: dict = {"others": raw}
    m = re.search(r"\bfor\s+(<?[^\s>;\n]+@[^\s>;\n]+>?)", raw, re.I)
    if m:
        result["for"] = m.group(1)
    return result


class MailAdapter:
    """Wraps email.message.Message with the attribute interface used by this module."""

    def __init__(self, msg):
        self._msg = msg
        self.text_plain: list[str] = []
        self.text_html: list[str] = []
        self.attachments: list[dict] = []
        self._from = _addr_list(msg, "from")
        self.to = _addr_list(msg, "to")
        self.cc = _addr_list(msg, "cc")
        self.bcc = _addr_list(msg, "bcc")
        self.delivered_to = _addr_list(msg, "delivered-to")
        self.subject = _str_header(msg.get("subject") or "")
        self.message_id = msg.get("message-id") or ""
        self.auto_submitted = msg.get("auto-submitted") or ""
        self.content_type = msg.get("content-type") or ""
        self.date = self._parse_date()
        self.received = [_parse_received(r) for r in msg.get_all("received") or []]
        self._walk_parts()

    def _parse_date(self):
        raw = self._msg.get("date")
        if not raw:
            return None
        try:
            return parsedate_to_datetime(raw)
        except Exception:
            pass
        try:
            t = parsedate(raw)
            if t:
                return datetime.datetime(*t[:6])
        except Exception:
            pass
        return None

    def _decode_text_part(self, part) -> str | None:
        payload = part.get_payload(decode=True)
        if payload is None:
            return None
        charset = part.get_content_charset("utf-8") or "utf-8"
        try:
            return payload.decode(charset, errors="replace")
        except LookupError:
            return payload.decode("utf-8", errors="replace")

    def _walk_parts(self):
        for part in self._msg.walk():
            if part.is_multipart():
                continue
            ctype = part.get_content_type()
            cdisp = (part.get_content_disposition() or "").lower()
            filename = part.get_filename()
            content_id = part.get("content-id") or ""

            if filename:
                filename = _str_header(filename)

            is_attachment = False
            if filename:
                is_attachment = True
            elif content_id and ctype not in ("text/plain", "text/html"):
                is_attachment = True
                filename = content_id
            elif part.get_content_subtype() == "rtf":
                is_attachment = True
                filename = f"{uuid.uuid4().hex}.rtf"
            elif cdisp == "attachment":
                is_attachment = True
                filename = f"{uuid.uuid4().hex}.txt"

            if is_attachment:
                payload = part.get_payload(decode=True)
                if payload is not None:
                    self.attachments.append({"filename": filename, "payload": payload})
            elif ctype == "text/plain":
                text = self._decode_text_part(part)
                if text is not None:
                    self.text_plain.append(text)
            elif ctype == "text/html":
                text = self._decode_text_part(part)
                if text is not None:
                    self.text_html.append(text)


def parse_mail_from_bytes(raw_bytes: bytes) -> MailAdapter:
    msg = BytesParser(policy=compat32).parsebytes(raw_bytes)
    return MailAdapter(msg)


def get_text(mail):
    raw_content, html_content, plain_content, html_quote, plain_quote = (
        "",
        "",
        "",
        "",
        "",
    )

    if mail.text_html:
        raw_content = "".join(mail.text_html).replace("\r\n", "\n")
        html_content, html_quote = strip_email_quote(raw_content)
        plain_content = html2text(html_content)

    if mail.text_plain or not plain_content:
        raw_content = "".join(mail.text_plain)
        plain_content = extract_non_quoted_from_plain(raw_content)
        plain_quote = exctract_quoted_from_plain(raw_content, plain_content)

    return {
        "html_content": html_content,
        "content": plain_content,
        "html_quote": html_quote,
        "quote": plain_quote,
    }


def get_auto_reply_type(mail):
    if "report-type=disposition-notification" in mail.content_type:
        return "disposition-notification"
    if mail.auto_submitted and mail.auto_submitted.lower() == "auto-replied":
        return "vacation-reply"
    return None


def get_to_plus(mail):
    to_plus = set(extract_emails(mail.to)) if mail.to else set()

    to_plus.update(extract_emails(mail.delivered_to))
    to_plus.update(extract_emails(mail.cc))
    to_plus.update(extract_emails(mail.bcc))
    to_plus.update(
        normalized
        for r in mail.received
        if "others" in r
        for match in [
            re.search(
                r"for ([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", r["others"]
            )
        ]
        if match
        for normalized in [validate_and_normalize(match.group(1))]
        if normalized
    )
    to_plus.update(
        normalized
        for r in mail.received
        if "for" in r
        for normalized in [validate_and_normalize(r["for"])]
        if normalized
    )
    return list(to_plus)


def get_attachments(mail):
    attachments = []
    for attachment in mail.attachments:
        filename = attachment["filename"]
        try:
            attachments.append((filename, BytesIO(attachment["payload"]), BINARY_MIME))
        except Exception:
            print(f"Unable to include attachment '{filename}' in {mail.message_id}\n")
    return attachments


def get_eml(raw_mail, compress_eml):
    content = raw_mail

    if compress_eml:
        file = BytesIO()
        with gzip.open(file, "wb") as f:
            f.write(raw_mail)
        content = file.getvalue()
    return content


def get_manifest(mail, compress_eml):
    return {
        "headers": {
            "subject": mail.subject,
            "to": extract_emails(mail.to),
            "to+": get_to_plus(mail),
            "from": extract_emails(mail._from),
            "date": mail.date.isoformat() if mail.date else [],
            "cc": extract_emails(mail.cc),
            "message_id": mail.message_id,
            "auto_reply_type": get_auto_reply_type(mail),
        },
        "version": "v2",
        "text": get_text(mail),
        "files_count": len(mail.attachments),
        "file_names": [{"filename": att["filename"]} for att in mail.attachments],
        "eml": {
            "compressed": compress_eml,
        },
    }


def serialize_mail(raw_mail, compress_eml=False):
    mail = parse_mail_from_bytes(raw_mail)
    files = []
    # Build manifest
    body = get_manifest(mail, compress_eml)
    files.append(
        (
            "manifest",
            ("manifest.json", BytesIO(json.dumps(body).encode("utf-8")), JSON_MIME),
        )
    )
    # Build eml
    eml_ext = "eml.gz" if compress_eml else "eml"
    eml_name = "{}.{}".format(uuid.uuid4().hex, eml_ext)
    eml_mime = GZ_MIME if compress_eml else EML_MIME

    files.append(
        ("eml", (eml_name, BytesIO(get_eml(raw_mail, compress_eml)), eml_mime))
    )
    # Build attachments
    for att in get_attachments(mail):
        files.append(("attachment", att))
    return files


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as fp:
        raw_mail = fp.read()
        mail = parse_mail_from_bytes(raw_mail)
        body = get_manifest(mail, False)
        json.dump(body, sys.stdout, indent=4)
