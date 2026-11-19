"""Bot management API."""

from __future__ import annotations

import asyncio
import logging
import subprocess
import sys
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from agent.manager.bot_manager import bot_manager
from agent.manager.account_store import account_store
from agent.schemas import (
    BotInfo, BotStartRequest, BatchStartRequest, BatchStopRequest,
    BatchResult, BotImportRequest, BotExportRequest, BotExportEntry,
    BotStatus, PurgeRequest, PurgeResponse, PurgeResultEntry,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["bots"])
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


@router.get("/api/listbot", response_model=list[BotInfo], response_model_exclude_none=True)
async def list_bots(
    bot_id: str | None = Query(None, description="Filter by bot_id (substring match)"),
):
    bots = bot_manager.list_bots()
    if bot_id:
        q = bot_id.lower()
        bots = [b for b in bots if q in (b.bot_id or '').lower()]
    return bots


@router.get("/api/bot/{bot_id}", response_model=BotInfo, response_model_exclude_none=True)
async def get_bot(bot_id: str):
    info = bot_manager.get_bot(bot_id)
    if info is None:
        raise HTTPException(status_code=404, detail=f"Bot '{bot_id}' not found")
    return info


@router.post("/api/startbot", response_model=BatchResult, response_model_exclude_none=True)
async def start_bots(req: BatchStartRequest):
    """Start bots concurrently. Mode: 'sync' (wait for logins) or 'fire' (return immediately)."""
    all_requests = list(req.bots) + [BotStartRequest(bot_id=bid) for bid in req.bot_ids]

    # ── Phase 1: Launch all bots concurrently ──
    async def _launch_one(bot_req: BotStartRequest) -> BotInfo:
        try:
            bot = await asyncio.to_thread(
                bot_manager.launch_bot,
                bot_id=bot_req.bot_id,
                env=bot_req.env.value if bot_req.env else None,
                proxy=bot_req.proxy,
                auto_login=bot_req.auto_login,
            )
            return BotInfo(bot_id=bot_req.bot_id, status=BotStatus.INITIAL, env=bot_req.env.value if bot_req.env else "")
        except ValueError as e:
            return BotInfo(bot_id=bot_req.bot_id, status=BotStatus.ERROR, error=str(e))
        except Exception as e:
            return BotInfo(bot_id=bot_req.bot_id, status=BotStatus.ERROR, error=str(e))

    launch_results = await asyncio.gather(*[_launch_one(r) for r in all_requests])
    launched_bots = [r for r in launch_results if r.status != BotStatus.ERROR]

    # ── Fire mode: return immediately ──
    if req.mode == "fire":
        success = len(launched_bots)
        errors = len(launch_results) - success
        return BatchResult(results=launch_results, success_count=success, error_count=errors)

    # ── Sync mode: wait for all logins concurrently ──
    async def _wait_one(bot_id: str) -> BotInfo:
        try:
            bot = await asyncio.to_thread(bot_manager.get_bot_instance, bot_id)
            if bot is None:
                return BotInfo(bot_id=bot_id, status=BotStatus.ERROR, error="Bot instance lost")
            return await asyncio.to_thread(bot_manager.wait_bot_login, bot)
        except Exception as e:
            return BotInfo(bot_id=bot_id, status=BotStatus.ERROR, error=str(e))

    login_results = await asyncio.gather(*[_wait_one(r.bot_id) for r in launched_bots])

    # Merge: errors from phase 1 + results from phase 2
    final_results = [r for r in launch_results if r.status == BotStatus.ERROR] + list(login_results)
    success = sum(1 for r in login_results if r.status == BotStatus.RUNNING)
    errors = len(final_results) - success
    return BatchResult(results=final_results, success_count=success, error_count=errors)


@router.post("/api/stopbot", response_model=BatchResult, response_model_exclude_none=True)
async def stop_bots(req: BatchStopRequest):
    results = []; success = 0; errors = 0
    for bot_id in req.bot_ids:
        info = bot_manager.stop_bot(bot_id)
        if info is None:
            results.append(BotInfo(bot_id=bot_id, status="ERROR", error="Bot not running")); errors += 1
        else:
            results.append(info); success += 1
    return BatchResult(results=results, success_count=success, error_count=errors)


@router.get("/api/bot/{bot_id}/local")
async def bot_local_state(bot_id: str):
    """本地账号目录是否可复用（有 axolotl.db 且 prekeys>0）。

    连接器恢复上号时据此跳过破坏性 import6，避免清 prekey 导致对方官方端消息 Invalid KeyId。
    路径必须用 bot_id（相对 profile 名），不能拼 ACCOUNT_PATH 再丢进 constructPath。
    """
    import sqlite3

    from core.common.tools import StorageTools
    from core.axolotl.factory import AxolotlManagerFactory

    dbpath = StorageTools.constructPath(bot_id, AxolotlManagerFactory.DB)
    prekey_count = 0
    ready = False
    if Path(dbpath).is_file():
        try:
            conn = sqlite3.connect(f"file:{dbpath}?mode=ro", uri=True)
            try:
                prekey_count = int(conn.execute("SELECT COUNT(*) FROM prekeys").fetchone()[0] or 0)
            finally:
                conn.close()
            ready = prekey_count > 0
        except Exception as e:  # noqa: BLE001
            logger.debug("bot local probe failed %s: %s", bot_id, e)
    from core.axolotl.rekey import read_rekey_request

    rekey_pending = read_rekey_request(str(Path(dbpath).parent))
    return {
        "bot_id": bot_id,
        "ready": ready,
        "prekey_count": prekey_count,
        "dbpath": dbpath,
        "rekey_pending": rekey_pending,
    }


class RekeyBotRequest(BaseModel):
    bot_ids: list[str] = Field(..., min_length=1, description="要重传公钥包的 bot（手机号）")


@router.post("/api/rekeybot", response_model=dict)
async def rekey_bots(req: RekeyBotRequest):
    """[salesquickly] SQ_REKEY：标记下次登录时向服务器重传整套公钥包。

    用于同号在别处登录过、服务器上的公钥包被覆盖、本实例收消息报 Invalid KeyId 的情况。
    只写标记，不改本地密钥；bot 正在运行时需要重新上线（断开 → 上线）才会生效。
    """
    from conf.constants import SysVar
    from core.axolotl.rekey import request_rekey

    results = {}
    for raw in req.bot_ids:
        bot_id = raw.strip()
        account_dir = Path(SysVar.ACCOUNT_PATH) / bot_id
        marked = account_dir.is_dir() and request_rekey(str(account_dir), "api_rekeybot")
        info = bot_manager.get_bot(bot_id)
        running = bool(info and info.status == BotStatus.RUNNING)
        results[bot_id] = {
            "marked": marked,
            "running": running,
            "error": None if marked else "local account dir missing",
            "next_step": "disconnect and log in again" if marked and running else None,
        }
    return {"results": results}


class EnsureBotRequest(BaseModel):
    bot_id: str = Field(..., min_length=1)
    env: str = Field("android", description="Device env name")


@router.post("/api/ensurebot", response_model=BotInfo, response_model_exclude_none=True)
async def ensure_bot(req: EnsureBotRequest):
    """跳过 import6 时：确认本地目录存在并登记到 account_store，供 startbot 使用。"""
    from conf.constants import SysVar

    bot_id = req.bot_id.strip()
    account_dir = Path(SysVar.ACCOUNT_PATH + bot_id)
    if not account_dir.is_dir():
        raise HTTPException(status_code=404, detail=f"Local account dir missing for '{bot_id}'")
    env = req.env or "android"
    account_store.register(bot_id, env=env)
    account_store.update_status(bot_id, "stopped", env=env)
    return BotInfo(bot_id=bot_id, status=BotStatus.STOPPED, env=env)


@router.post("/api/importbot", response_model=BatchResult, response_model_exclude_none=True)
async def import_accounts(req: BotImportRequest):
    results = []; success = 0; errors = 0
    for item in req.accounts:
        if not item.data or item.data.count(",") != 5:
            phone = item.data.split(",")[0].strip() if item.data else "unknown"
            results.append(BotInfo(bot_id=phone, status="ERROR", error="Invalid CSV (need 6 fields)")); errors += 1; continue
        phone = item.data.split(",")[0].strip()
        if not phone:
            results.append(BotInfo(bot_id="unknown", status="ERROR", error="No phone")); errors += 1; continue
        env = item.env.value
        cmd = [sys.executable, str(_PROJECT_ROOT / "script" / "import6.py"), item.data, "--env", env]
        try:
            r = subprocess.run(cmd, cwd=str(_PROJECT_ROOT), capture_output=True, text=True, timeout=30)
            if r.returncode != 0:
                results.append(BotInfo(bot_id=phone, status="ERROR", error=f"Import failed: {r.stderr[:200]}")); errors += 1
            else:
                account_store.register(phone, env=env)
                account_store.update_status(phone, "stopped", env=env)
                results.append(BotInfo(bot_id=phone, status="STOPPED")); success += 1
        except subprocess.TimeoutExpired:
            results.append(BotInfo(bot_id=phone, status="ERROR", error="Timeout")); errors += 1
        except Exception as e:
            results.append(BotInfo(bot_id=phone, status="ERROR", error=str(e))); errors += 1
    return BatchResult(results=results, success_count=success, error_count=errors)


@router.post("/api/exportbot", response_model=dict)
async def export_accounts(req: BotExportRequest):
    """Export accounts. Returns {bot_id: {data: csv, env: str}}."""
    result = {}
    for bot_id in req.bot_ids:
        # Resolve env from account store or bot manager
        env = ""
        acct = account_store.get(bot_id)
        if acct:
            env = acct.get("env", "")
        if not env:
            info = bot_manager.get_bot(bot_id)
            if info:
                env = info.env or ""

        cmd = [sys.executable, str(_PROJECT_ROOT / "script" / "export6.py"), bot_id]
        try:
            r = subprocess.run(cmd, cwd=str(_PROJECT_ROOT), capture_output=True, text=True, timeout=30)
            data = r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None
        except Exception:
            data = None
        result[bot_id] = {"data": data, "env": env}
    return {"exports": result}


@router.post("/api/purgebot", response_model=PurgeResponse, response_model_exclude_none=True)
async def purge_accounts(req: PurgeRequest):
    """Permanently delete bot accounts: stop bot, remove DB record, delete local data directory.

    mode="auto": purge ALL accounts that are auth_failed OR orphaned (DB entry with no data dir).
    mode="list": purge only specified bot_ids that are in auth_failed state.

    Use with caution — this operation cannot be undone.
    """
    raw_results = await asyncio.to_thread(
        bot_manager.purge_accounts,
        mode=req.mode,
        bot_ids=req.bot_ids,
    )
    results = {
        bot_id: PurgeResultEntry(**entry)
        for bot_id, entry in raw_results.items()
    }
    return PurgeResponse(results=results)


@router.delete("/api/bot/{bot_id}", response_model=dict)
async def delete_bot(bot_id: str):
    """Delete a single bot account: stop it, remove from DB, and delete its
    local data directory. Usable for any status (not just auth_failed)."""
    import shutil
    from pathlib import Path
    from conf.constants import SysVar

    # 1. Stop bot if running
    try:
        bot_manager.stop_bot(bot_id, join_timeout=5.0)
    except Exception:
        pass

    # 2. Remove from account store DB
    existed = account_store.remove(bot_id)

    # 3. Delete local data directory
    dir_removed = False
    acct_dir = Path(SysVar.ACCOUNT_PATH) / bot_id
    if acct_dir.exists():
        shutil.rmtree(str(acct_dir))
        dir_removed = True

    return {"bot_id": bot_id, "existed": existed, "dir_removed": dir_removed}


@router.post("/api/scan", response_model=dict)
async def scan_accounts():
    """Re-scan the account directory on disk to sync the database.

    - New directories on disk → added to DB
    - DB entries with no disk directory → purged (orphaned)
    """
    count_before = len(account_store.list_all())
    added, orphaned = account_store._migrate_from_filesystem()
    count_after = len(account_store.list_all())
    return {
        "scan_complete": True,
        "accounts_before": count_before,
        "accounts_after": count_after,
        "added": added,
        "orphaned": orphaned,
    }
