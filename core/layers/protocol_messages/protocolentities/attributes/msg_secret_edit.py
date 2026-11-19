"""Decrypt WhatsApp secretEncryptedMessage MESSAGE_EDIT envelopes.

Newer clients seal edits with the original message's messageSecret (HKDF-SHA256
+ AES-256-GCM, empty AAD, use-case literal \"Message Edit\"). See whatsmeow
msgsecret.go / Baileys decryptMessageEdit.
"""

from __future__ import annotations

import logging
from typing import List, Optional, Sequence, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from proto import e2e_pb2

logger = logging.getLogger(__name__)

_ENC_MESSAGE_EDIT = "Message Edit"
# e2e.SecretEncryptedMessage.SecretEncType.MESSAGE_EDIT
_SECRET_ENC_TYPE_MESSAGE_EDIT = 2


def bare_jid(jid: Optional[str]) -> str:
    if not jid:
        return ""
    user, sep, host = jid.partition("@")
    if not sep:
        return user.split(":", 1)[0]
    user = user.split(":", 1)[0]
    return f"{user}@{host}"


def _jid_candidates(*jids: Optional[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for jid in jids:
        bare = bare_jid(jid)
        if not bare or bare in seen:
            continue
        seen.add(bare)
        out.append(bare)
        # LID ↔ PN 互换候选（GCM 会拒绝错误组合）
        if bare.endswith("@lid"):
            alt = bare[: -len("@lid")] + "@s.whatsapp.net"
        elif bare.endswith("@s.whatsapp.net"):
            alt = bare[: -len("@s.whatsapp.net")] + "@lid"
        else:
            continue
        if alt not in seen:
            seen.add(alt)
            out.append(alt)
    return out


def derive_message_edit_key(
    message_secret: bytes, msg_id: str, orig_sender: str, editor: str
) -> bytes:
    info = (
        msg_id.encode("utf-8")
        + orig_sender.encode("utf-8")
        + editor.encode("utf-8")
        + _ENC_MESSAGE_EDIT.encode("utf-8")
    )
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(message_secret)


def decrypt_message_edit(
    *,
    message_secret: bytes,
    enc_payload: bytes,
    enc_iv: bytes,
    msg_id: str,
    orig_sender_candidates: Sequence[str],
    editor_candidates: Sequence[str],
) -> Optional[e2e_pb2.Message]:
    if not message_secret or not enc_payload or not enc_iv or not msg_id:
        return None
    if len(enc_iv) != 12:
        logger.warning("MESSAGE_EDIT enc_iv length=%s (want 12)", len(enc_iv))
        return None

    for orig in orig_sender_candidates:
        for editor in editor_candidates:
            try:
                key = derive_message_edit_key(message_secret, msg_id, orig, editor)
                plaintext = AESGCM(key).decrypt(enc_iv, enc_payload, b"")
            except Exception:  # noqa: BLE001 — GCM auth fail / bad key
                continue
            try:
                msg = e2e_pb2.Message()
                msg.ParseFromString(plaintext)
                return msg
            except Exception:  # noqa: BLE001
                logger.warning(
                    "MESSAGE_EDIT plaintext parse failed id=%s", msg_id, exc_info=True
                )
                return None
    return None


def extract_edit_text(inner: e2e_pb2.Message) -> Optional[str]:
    """Pull new body from decrypted edit Message (protocol.edited_message or bare)."""
    proto = inner

    def _has(obj, name: str) -> bool:
        try:
            return bool(obj.HasField(name))
        except Exception:  # noqa: BLE001
            return False

    if _has(proto, "protocol_message"):
        pm = proto.protocol_message
        if _has(pm, "edited_message"):
            proto = pm.edited_message
    if _has(proto, "device_sent_message"):
        proto = proto.device_sent_message.message
    # Message.editedMessage (field 58) = FutureProofMessage
    for fname in ("editedMessage", "edited_message"):
        if _has(proto, fname):
            fp = getattr(proto, fname)
            if hasattr(fp, "message"):
                proto = fp.message
            break

    text = (proto.conversation or "").strip()
    if text:
        return text
    if _has(proto, "extended_text_message"):
        text = (proto.extended_text_message.text or "").strip()
        if text:
            return text
    return None


def _msg_get(obj, *names: str):
    for name in names:
        if hasattr(obj, name):
            try:
                if hasattr(obj, "HasField") and obj.DESCRIPTOR.fields_by_name.get(name):
                    if not obj.HasField(name):
                        continue
            except Exception:  # noqa: BLE001
                pass
            val = getattr(obj, name)
            if val is not None and val != b"" and val != "":
                return val
    return None


def _has_secret_edit(outer: e2e_pb2.Message) -> bool:
    for name in ("secretEncryptedMessage", "secret_encrypted_message"):
        try:
            if outer.HasField(name):
                return True
        except Exception:  # noqa: BLE001
            continue
    return False


def try_unwrap_secret_edit(
    outer: e2e_pb2.Message,
    *,
    editor_jid: str,
    message_secret: bytes,
    stored_orig_sender: Optional[str] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """Return (edit_of_id, new_text) or (None, None)."""
    if not _has_secret_edit(outer):
        return None, None
    enc = _msg_get(outer, "secretEncryptedMessage", "secret_encrypted_message")
    if enc is None:
        return None, None

    enc_type = _msg_get(enc, "secretEncType", "secret_enc_type")
    if enc_type is None:
        enc_type = getattr(enc, "secretEncType", None)
        if enc_type is None:
            enc_type = getattr(enc, "secret_enc_type", None)
    if int(enc_type or 0) != _SECRET_ENC_TYPE_MESSAGE_EDIT:
        return None, None

    key = _msg_get(enc, "targetMessageKey", "target_message_key")
    if key is None:
        return None, None

    edit_of = getattr(key, "id", None) or ""
    if not edit_of:
        return None, None

    from_me = bool(getattr(key, "from_me", False))
    editor_cands = _jid_candidates(editor_jid)
    if from_me:
        # 对方编辑自己的消息：原发送者 = 编辑者
        orig_cands = _jid_candidates(editor_jid, stored_orig_sender)
    else:
        orig_cands = _jid_candidates(
            getattr(key, "participant", None) or None,
            getattr(key, "remote_jid", None) or None,
            stored_orig_sender,
            editor_jid,
        )

    if not editor_cands or not orig_cands:
        logger.warning("MESSAGE_EDIT missing jid candidates id=%s", edit_of)
        return None, None

    enc_payload = _msg_get(enc, "encPayload", "enc_payload")
    enc_iv = _msg_get(enc, "encIV", "enc_iv")
    if not enc_payload or not enc_iv:
        return None, None

    inner = decrypt_message_edit(
        message_secret=message_secret,
        enc_payload=bytes(enc_payload),
        enc_iv=bytes(enc_iv),
        msg_id=edit_of,
        orig_sender_candidates=orig_cands,
        editor_candidates=editor_cands,
    )
    if inner is None:
        logger.warning(
            "MESSAGE_EDIT decrypt failed id=%s editors=%s origs=%s",
            edit_of,
            editor_cands,
            orig_cands,
        )
        return None, None

    text = extract_edit_text(inner)
    if not text:
        logger.warning("MESSAGE_EDIT decrypted but no text id=%s", edit_of)
        return None, None
    return edit_of, text
