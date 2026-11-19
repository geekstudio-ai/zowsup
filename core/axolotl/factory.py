from ..axolotl.manager import AxolotlManager
from ..common.tools import StorageTools
from ..axolotl.store.sqlite.liteaxolotlstore import LiteAxolotlStore
import logging
import os
from typing import Optional, Any

logger = logging.getLogger(__name__)


class AxolotlManagerFactory:
    DB = "axolotl.db"

    def get_manager(self, profile_name: str, username: str) -> "AxolotlManager":
        logger.debug(f"get_manager(profile_name={profile_name}, username={username})")
        dbpath = StorageTools.constructPath(profile_name, self.DB)
        store = LiteAxolotlStore(dbpath)
        manager = AxolotlManager(store, username)
        # [salesquickly] SQ_REKEY：记录账号目录，供重传标记读写
        manager.db_dir = os.path.dirname(dbpath)
        return manager
    


    

