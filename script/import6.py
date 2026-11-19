import sys,os
sys.path.append(os.getcwd())

from core.profile.profile import YowProfile
import base64
import sqlite3
from core.axolotl.factory import AxolotlManagerFactory
from conf.constants import SysVar
from core.config.v1.config import Config
from consonance.structs.keypair import KeyPair
from pathlib import Path
from core.config.transforms.dict_json import DictJsonTransform
from core.config.v1.serialize import ConfigSerialize
from common.utils import Utils
import logging
import names
from core.common.tools import WATools, StorageTools
from common.consolemain import ConsoleMain

logger = logging.getLogger(__name__)


def _decode_identity_keys(data):
    if len(base64.b64decode(data[3])) == 32:
        pub_key = b"\x05" + base64.b64decode(data[3])
    else:
        logger.info("6 parts account may be wrong")
        pub_key = base64.b64decode(data[3])
    priv_key = base64.b64decode(data[4])
    return pub_key, priv_key


def _probe_local_crypto(phone, pub_key, priv_key):
    """只读探测本地 axolotl：身份是否与六段号一致、prekey 数量。

    不用 AxolotlManager 打开库，避免 Windows 下多连接锁库、干扰后续导入。
    """
    dbpath = StorageTools.constructPath(phone, AxolotlManagerFactory.DB)
    if not os.path.isfile(dbpath):
        return False, 0
    try:
        conn = sqlite3.connect(f"file:{dbpath}?mode=ro", uri=True)
        try:
            row = conn.execute(
                "SELECT public_key, private_key FROM identities "
                "WHERE recipient_id=-1 AND recipient_type=0"
            ).fetchone()
            if not row or row[0] != pub_key or row[1] != priv_key:
                return False, 0
            prekey_count = int(conn.execute("SELECT COUNT(*) FROM prekeys").fetchone()[0] or 0)
            return True, prekey_count
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        logger.warning("[salesquickly] import6 probe failed for %s", phone, exc_info=True)
        return False, 0


class Import6(ConsoleMain):
    def run(self,params,options):
        Utils.init_log(logging.INFO,"import6.log")

        self.commonOptionsProcess(options)

        if "env" not in options:
            logger.info("set default env to android")
            options["env"] = "android"

        regType,osType = Utils.getTypesByEnvName(options["env"])

        if len(params) == 0:
            print("data must be specified")
            sys.exit(1)

        auto = ("auto" in options)

        data = params[0].split(",")

        client_static_keypair_str = base64.b64encode(base64.b64decode(data[2]) + base64.b64decode(data[1])).decode()
        kp = KeyPair.from_bytes(base64.b64decode(client_static_keypair_str))

        if len(data[5]) % 4 !=0:
            data[5] = data[5]+'=' * (4- len(data[5]) % 4)
        sixth = base64.b64decode(data[5])
        #pos = sixth.find('#'.encode())
        id = sixth[-20:]

        pubKey, privKey = _decode_identity_keys(data)
        phone = data[0]

        # [salesquickly] 同身份且已有 prekeys：完全不动本地目录，避免写坏 config / 清密钥。
        same_identity, prekey_count = _probe_local_crypto(phone, pubKey, privKey)
        if same_identity and prekey_count > 0:
            # SQ_REKEY：重新导入同一个号，通常是因为这个号在别处登录过、本地收不到消息。
            # 本地密钥不动，但标记下次登录时把公钥包重传到服务器（自动重连走 ensurebot，不经过这里）。
            from core.axolotl.rekey import request_rekey
            request_rekey(
                os.path.dirname(StorageTools.constructPath(phone, AxolotlManagerFactory.DB)),
                "import6_reuse",
            )
            logger.info(
                "[salesquickly] import6 reuse local crypto phone=%s prekeys=%s (rekey on next login)",
                phone,
                prekey_count,
            )
            print("IMPORT6_REUSE")
            return

        if same_identity and prekey_count == 0:
            logger.info(
                "[salesquickly] import6 same identity but prekeys empty, will refill: %s",
                phone,
            )

        config = Config(
            pushname=names.get_full_name()+"X",
            cc=Utils.getMobileCC(phone),
            mcc='000',
            mnc='000',
            phone=phone,
            sim_mcc='000',
            sim_mnc='000',
            client_static_keypair = kp,
            fdid = WATools.generatePhoneId(self.env),
            expid= WATools.generateDeviceId(),
            id = id
        )

        config.os_name = SysVar.OS_NAME_MAPPING.get(options["env"],"Android")

        account_dir = Path(SysVar.ACCOUNT_PATH+phone)
        if not account_dir.exists():
            account_dir.mkdir()

        profile = YowProfile(SysVar.ACCOUNT_PATH+phone)
        profile.write_config(config)

        db = AxolotlManagerFactory().get_manager(SysVar.ACCOUNT_PATH+phone, phone)

        # 身份已一致只是 prekey 空：不要再 DELETE（本来就空）；身份变更才清
        if not same_identity:
            db._store.identityKeyStore.dbConn.execute("DELETE FROM prekeys")
            logger.info("[salesquickly] import6 cleared prekeys (new/changed identity): %s", phone)

        q = "UPDATE identities SET public_key=? , private_key=? WHERE recipient_id=-1 AND recipient_type=0"
        c = db._store.identityKeyStore.dbConn.cursor()
        c.execute(q, (pubKey,privKey))
        db._store.identityKeyStore.dbConn.commit()
        jsonstr = DictJsonTransform().transform(ConfigSerialize(config.__class__).serialize(config))
        publicKey = Utils.b64str(pubKey)
        privateKey = Utils.b64str(privKey)
        logger.info("===PART1-REGKEYS===")
        logger.info(db.registration_id)
        logger.info(publicKey)
        logger.info(privateKey)
        logger.info("===PART2-PROFILE===")
        logger.info(jsonstr)


if __name__ == "__main__":

    SysVar.loadConfig()

    params,options = Utils.cmdLineParser(sys.argv)

    Import6().run(params,options)
