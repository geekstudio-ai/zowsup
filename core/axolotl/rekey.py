"""[salesquickly] SQ_REKEY：标记「下次登录时向服务器重传整套公钥包」。

背景：同一六段号在另一个 agent / 设备上导入并登录后，对方会用自己的
registration / signed prekey / prekeys 覆盖服务器上的公钥包。本实例之后重新
上线时，本地 prekey 全部标记为已上传，不会再 flush，服务器上一直是对方的公钥包，
联系人新建会话发来的 pkmsg 在本地报 Invalid KeyId，消息被丢弃。

做法：在账号目录（axolotl.db 所在目录）放一个标记文件。bot 连上时
（AxolotlControlLayer.on_connected）发现标记，就生成新的 signed prekey 和一批
新 prekey（未上传），交给现有的 PASSIVE 流程在登录后上传，然后删除标记。

写标记的地方：
- 收到 stream:error conflict（被别处抢登）
- import6 命中 IMPORT6_REUSE（用户重新导入同一个号）
- agent POST /api/rekeybot（运维手动触发）

普通自动重连不写标记，不会每次重连都重传。
"""
from __future__ import annotations

import logging
import os
import time
from typing import Optional

logger = logging.getLogger(__name__)

REKEY_MARKER = ".sq_rekey_needed"


def _marker_path(account_dir: Optional[str]) -> Optional[str]:
    if not account_dir:
        return None
    return os.path.join(account_dir, REKEY_MARKER)


def request_rekey(account_dir: Optional[str], reason: str) -> bool:
    """写入重传标记。账号目录不存在时返回 False。"""
    path = _marker_path(account_dir)
    if not path or not os.path.isdir(account_dir):
        logger.warning("[salesquickly] request_rekey skipped, account dir missing: %s", account_dir)
        return False
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("{} {}\n".format(int(time.time()), reason))
        logger.info("[salesquickly] rekey requested: dir=%s reason=%s", account_dir, reason)
        return True
    except OSError:
        logger.warning("[salesquickly] request_rekey failed: %s", path, exc_info=True)
        return False


def read_rekey_request(account_dir: Optional[str]) -> Optional[str]:
    """有标记时返回原因（文件内容），没有返回 None。"""
    path = _marker_path(account_dir)
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip() or "unknown"
    except OSError:
        return "unknown"


def clear_rekey_request(account_dir: Optional[str]) -> None:
    path = _marker_path(account_dir)
    if not path:
        return
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    except OSError:
        logger.warning("[salesquickly] clear rekey marker failed: %s", path, exc_info=True)
