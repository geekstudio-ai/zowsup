"""Persist inbound messageSecret for later secretEncryptedMessage decrypt (edits etc.)."""

from __future__ import annotations

import logging
import time
from typing import Any, Optional, Tuple

logger = logging.getLogger(__name__)


class LiteMsgSecretStore:
    def __init__(self, dbConn) -> None:
        self.dbConn = dbConn
        dbConn.execute(
            "CREATE TABLE IF NOT EXISTS msg_secrets ("
            "msg_id TEXT PRIMARY KEY,"
            "secret BLOB NOT NULL,"
            "sender_jid TEXT,"
            "timestamp INTEGER)"
        )
        # 旧消息过多时按时间清理；主键已是 msg_id，查询 O(1)
        dbConn.execute(
            "CREATE INDEX IF NOT EXISTS idx_msg_secrets_ts ON msg_secrets(timestamp)"
        )

    def store(self, msg_id: str, secret: bytes, sender_jid: Optional[str] = None) -> None:
        if not msg_id or not secret:
            return
        try:
            self.dbConn.cursor().execute(
                "INSERT OR REPLACE INTO msg_secrets(msg_id, secret, sender_jid, timestamp) "
                "VALUES(?,?,?,?)",
                (msg_id, secret, sender_jid, int(time.time())),
            )
            self.dbConn.commit()
        except Exception:  # noqa: BLE001
            logger.warning("msg_secrets store failed id=%s", msg_id, exc_info=True)

    def get(self, msg_id: str) -> Tuple[Optional[bytes], Optional[str]]:
        if not msg_id:
            return None, None
        try:
            row = (
                self.dbConn.cursor()
                .execute(
                    "SELECT secret, sender_jid FROM msg_secrets WHERE msg_id = ?",
                    (msg_id,),
                )
                .fetchone()
            )
            if not row:
                return None, None
            return row[0], (row[1].decode("utf-8") if isinstance(row[1], bytes) else row[1])
        except Exception:  # noqa: BLE001
            logger.warning("msg_secrets get failed id=%s", msg_id, exc_info=True)
            return None, None

    def prune(self, keep_seconds: int = 14 * 24 * 3600) -> Any:
        cutoff = int(time.time()) - keep_seconds
        try:
            self.dbConn.cursor().execute(
                "DELETE FROM msg_secrets WHERE timestamp < ?", (cutoff,)
            )
            self.dbConn.commit()
        except Exception:  # noqa: BLE001
            logger.warning("msg_secrets prune failed", exc_info=True)
