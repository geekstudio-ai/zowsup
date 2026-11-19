from ....structs import ProtocolTreeNode
from typing import Optional, Any, List, Dict, Union
from ....layers.protocol_receipts.protocolentities import OutgoingReceiptProtocolEntity
from ....layers.axolotl.protocolentities.iq_keys_get_result import ResultGetKeysIqProtocolEntity


class RetryOutgoingReceiptProtocolEntity(OutgoingReceiptProtocolEntity):

    '''
    <receipt type="retry" to="xxxxxxxxxxx@s.whatsapp.net" participant="" id="1415389947-12" t="1432833777">
        <retry count="1" t="1432833266" id="1415389947-12" v="1">
        </retry>
        <registration>
            HEX:xxxxxxxxx
        </registration>
    </receipt>
    '''

    def __init__(self, _id, jid, local_registration_id, retry_timestamp, v=1, count=1, participant=None, keys=None) -> None:
        super().__init__(_id, jid, participant=participant)
        '''
            Note to self: Android clients won't retry sending if the retry node didn't contain the message timestamp
        '''
        self.local_registration_id = local_registration_id
        self.v = v
        self.retry_timestamp = retry_timestamp
        self.count = count
        # [salesquickly] SQ_RETRY_KEYS：AxolotlManager.build_retry_keys() 的结果，None 表示不附带
        self.keys = keys

    @property
    def local_registration_id(self) -> Any:
        return self._local_registration_id

    @local_registration_id.setter
    def local_registration_id(self, value: Any) -> None:
        self._local_registration_id = value

    @property
    def v(self) -> Any:
        return self._v

    @v.setter
    def v(self, value: Any) -> None:
        self._v = value

    @property
    def retry_timestamp(self) -> Any:
        return self._retry_timestamp

    @retry_timestamp.setter
    def retry_timestamp(self, value: Any) -> None:
        self._retry_timestamp = value

    @property
    def count(self) -> Any:
        return self._count

    @count.setter
    def count(self, value: Any) -> None:
        self._count = value

    def toProtocolTreeNode(self) -> Any:
        node = super().toProtocolTreeNode()
        node.setAttribute("type", "retry")
        retry_attrs = {
            "count": str(self.count),
            "id":self.getId(),
            "v":str(self.v),
            "t":  str(self.retry_timestamp),
            
        }

        
        retry = ProtocolTreeNode("retry", retry_attrs)
        node.addChild(retry)
        registration = ProtocolTreeNode(
            "registration",
            data=ResultGetKeysIqProtocolEntity._intToBytes(self.local_registration_id)
        )
        node.addChild(registration)

        # [salesquickly] SQ_RETRY_KEYS：附带本地公钥包，格式与 baileys sendRetryRequest 一致。
        # 对方据此直接建立新会话，不再去服务器取（可能已被别处登录的同号覆盖的）公钥包。
        # zowsup 是主设备，没有 ADV 签名身份，所以不带 device-identity。
        if self.keys:
            k = self.keys
            node.addChild(ProtocolTreeNode("keys", children=[
                ProtocolTreeNode("type", data=b"\x05"),
                ProtocolTreeNode("identity", data=k["identity"]),
                ProtocolTreeNode("key", children=[
                    ProtocolTreeNode("id", data=int(k["prekey_id"]).to_bytes(3, "big")),
                    ProtocolTreeNode("value", data=k["prekey"]),
                ]),
                ProtocolTreeNode("skey", children=[
                    ProtocolTreeNode("id", data=int(k["skey_id"]).to_bytes(3, "big")),
                    ProtocolTreeNode("value", data=k["skey"]),
                    ProtocolTreeNode("signature", data=k["skey_signature"]),
                ]),
            ]))

        return node

    def __str__(self):
        out = super().__str__()
        return out

    @staticmethod
    def fromProtocolTreeNode(node):
        entity = OutgoingReceiptProtocolEntity.fromProtocolTreeNode(node)
        entity.__class__ = RetryOutgoingReceiptProtocolEntity
        retry_node = node.getChild("retry")
        entity.setRetryData(
            ResultGetKeysIqProtocolEntity._bytesToInt(
                node.getChild("registration").data
            ),
            retry_node["v"], retry_node["count"], retry_node["t"]
        )

        return entity

    @staticmethod
    def fromMessageNode(message_node, local_registration_id, keys=None):
        return RetryOutgoingReceiptProtocolEntity(
            message_node.getAttributeValue("id"),
            message_node.getAttributeValue("from"),
            local_registration_id,
            message_node.getAttributeValue("t"),
            participant=message_node.getAttributeValue("participant"),
            keys=keys,
        )
