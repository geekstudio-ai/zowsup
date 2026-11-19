from .layer_base import AxolotlBaseLayer
from typing import Optional, Any, List, Dict, Union

from ...layers.protocol_receipts.protocolentities import OutgoingReceiptProtocolEntity
from proto.e2e_pb2 import Message
from ...layers.axolotl.protocolentities import *
from ...layers.protocol_messages.protocolentities.proto import ProtoProtocolEntity
from ...layers.axolotl.props import PROP_IDENTITY_AUTOTRUST
from ...axolotl import exceptions
from core.common.tools import WATools

from axolotl.untrustedidentityexception import UntrustedIdentityException

import logging
logger = logging.getLogger(__name__)


class AxolotlReceivelayer(AxolotlBaseLayer):
    def __init__(self) -> None:
        super().__init__()
        self.v2Jids = [] #people we're going to send v2 enc messages
        self.sessionCiphers = {}
        self.groupCiphers = {}
        self.pendingIncomingMessages = {} #(jid, participantJid?) => message
        self._retries = {}

    async def receive(self, protocolTreeNode) -> Any:
        """
        :type protocolTreeNode: ProtocolTreeNode
        """        
        if not await self.processIqRegistry(protocolTreeNode):            
            if protocolTreeNode.tag == "message":
                await self.onMessage(protocolTreeNode)
            elif not protocolTreeNode.tag == "receipt":
                #receipts will be handled by send layer                
                await self.toUpper(protocolTreeNode)            

    async def processPendingIncomingMessages(self, jid, participantJid = None) -> Any:
        conversationIdentifier = (jid, participantJid)
        if conversationIdentifier in self.pendingIncomingMessages:
            for messageNode in self.pendingIncomingMessages[conversationIdentifier]:
                await self.onMessage(messageNode)

            del self.pendingIncomingMessages[conversationIdentifier]

    async def onMessage(self, protocolTreeNode) -> Any:          
        encNode = protocolTreeNode.getChild("enc")                
        if encNode:            
            await self.handleEncMessage(protocolTreeNode)
        else:
            await self.toUpper(protocolTreeNode)

    async def handleEncMessage(self, node) -> Any:                                
        encMessageProtocolEntity = EncryptedMessageProtocolEntity.fromProtocolTreeNode(node)       
        isGroup =  node["participant"] is not None
        senderJid = node["participant"] if isGroup else node["from"]
        if node.getChild("enc")["v"] == "2" and node["from"] not in self.v2Jids:
            self.v2Jids.append(node["from"])
        try:
            handled = False                        
            if encMessageProtocolEntity.getEnc(EncProtocolEntity.TYPE_SKMSG):                
                handled = await self.handleSenderKeyMessage(node)                           
                           
            if not handled:                                                                 
                if encMessageProtocolEntity.getEnc(EncProtocolEntity.TYPE_PKMSG):
                    await self.handlePreKeyWhisperMessage(node)                    
                elif encMessageProtocolEntity.getEnc(EncProtocolEntity.TYPE_MSG):
                    await self.handleWhisperMessage(node)                          
                else:
                    #兜底处理
                    await self.toLower(OutgoingReceiptProtocolEntity(node["id"], node["from"], participant=node["participant"]).toProtocolTreeNode())              

            self.reset_retries(node["id"])

        except exceptions.InvalidKeyIdException:
            # [salesquickly] 六段号换机/换栈后，对方仍用旧 session 加密时常见 Invalid KeyId。
            # 上游直接 ACK 丢弃会导致「已上线却收不到消息」；改为与 InvalidMessage 一样发 retry，
            # 让对方用新 prekey/session 重推。仍失败满 3 次再 ACK 放弃。
            # SQ_RETRY_KEYS：retry 必须附带本地公钥包。否则对方仍去服务器取公钥包，而服务器上的
            # 公钥包可能已被别处登录的同号覆盖，重推多少次都解不开。
            author = encMessageProtocolEntity.getAuthor(False)
            if node["id"] in self._retries and self._retries[node["id"]] >= 3:
                logger.warning(
                    "Invalid KeyId for {} after retries, sending receipt to drop".format(author)
                )
                await self.toLower(
                    OutgoingReceiptProtocolEntity(
                        node["id"], node["from"], participant=node["participant"]
                    ).toProtocolTreeNode()
                )
            else:
                logger.warning(
                    "Invalid KeyId for {}, requesting retry ({}/3)".format(
                        author, self._retries.get(node["id"], 0) + 1
                    )
                )
                import asyncio
                await asyncio.sleep(1)
                await self.send_retry(node, self.manager.registration_id, include_keys=True)

        except exceptions.InvalidMessageException:
            logger.warning("InvalidMessage for {}".format(encMessageProtocolEntity.getAuthor(False)))     
            if node["id"] in self._retries and self._retries[node["id"]] >=3:
                #重复三次，如果都是invalid可能是对方的异常，放弃,也有可能是本地的prekey变更，导致对方用的key无法解密
                await self.toLower(OutgoingReceiptProtocolEntity(node["id"], node["from"], participant=node["participant"]).toProtocolTreeNode())   
            else:            
                import asyncio
                await asyncio.sleep(1)
                await self.send_retry(node, self.manager.registration_id)                

        except exceptions.NoSessionException:            
            logger.warning("No session for {}, getting their keys now".format(encMessageProtocolEntity.getAuthor(False)))   
            #self.toLower(OutgoingReceiptProtocolEntity(node["id"], node["from"], participant=node["participant"]).toProtocolTreeNode())  

            conversationIdentifier = (node["from"], node["participant"])

            if conversationIdentifier not in self.pendingIncomingMessages:
                self.pendingIncomingMessages[conversationIdentifier] = []
            self.pendingIncomingMessages[conversationIdentifier].append(node)

            successJids, errorJids = await self.getKeysFor(
                [encMessageProtocolEntity.getAuthor(True)],
                errorClbk=lambda err, b: self.toLower(
                    OutgoingReceiptProtocolEntity(node["id"], node["from"], participant=node["participant"]).toProtocolTreeNode()
                )
            )
            if len(successJids):
                await self.processPendingIncomingMessages(*conversationIdentifier)
        except exceptions.DuplicateMessageException:
            logger.warning("Received a message that we've previously decrypted, "
                           "going to send the delivery receipt myself")        
            await self.toLower(OutgoingReceiptProtocolEntity(node["id"], node["from"], participant=node["participant"]).toProtocolTreeNode())    

        except UntrustedIdentityException as e:
            if self.getProp(PROP_IDENTITY_AUTOTRUST, False):
                logger.warning("Autotrusting identity for {}".format(e.getName()))
                self.manager.trust_identity(e.getName(), e.getIdentityKey())
                return await self.handleEncMessage(node)
            else:                
                logger.error("Ignoring message with untrusted identity")
                await self.toLower(OutgoingReceiptProtocolEntity(node["id"], node["from"], participant=node["participant"]).toProtocolTreeNode())    

    def handleMsMessage(self,node) -> Any:

        pass

        '''
        msMessageProtocolEntity = EncryptedMessageProtocolEntity.fromProtocolTreeNode(node)
        enc = msMessageProtocolEntity.getEnc(EncProtocolEntity.TYPE_MSMSG)
        plaintext = self.manager.decrypt_msg(msMessageProtocolEntity.getAuthor(False), enc.getData(),
                                               enc.getVersion() == 2)

        if enc.getVersion() == 2:
            self.parseAndHandleMessageProto(msMessageProtocolEntity, plaintext)

        node = msMessageProtocolEntity.toProtocolTreeNode()
        print(node)
        node.addChild((ProtoProtocolEntity(plaintext, enc.getMediaType())).toProtocolTreeNode())
        '''


    async def handlePreKeyWhisperMessage(self, node) -> Any:
        pkMessageProtocolEntity = EncryptedMessageProtocolEntity.fromProtocolTreeNode(node)
        enc = pkMessageProtocolEntity.getEnc(EncProtocolEntity.TYPE_PKMSG)

        if pkMessageProtocolEntity.getCategory()=="peer":
            _,_, deviceId = WATools.jidDecode(pkMessageProtocolEntity.getAuthor(True))
            lid,_,_ =  WATools.jidDecode(self.getProp("profile").config.lid)            
            sender_id = lid+":"+str(deviceId)+"@lid"            
        else:
            sender_id = pkMessageProtocolEntity.getAuthor(True)

        plaintext = self.manager.decrypt_pkmsg(sender_id, enc.getData(),
                                               enc.getVersion() == 2)

        if enc.getVersion() == 2:
            self.parseAndHandleMessageProto(pkMessageProtocolEntity, plaintext)

        node = pkMessageProtocolEntity.toProtocolTreeNode()
        node.addChild((ProtoProtocolEntity(plaintext, enc.getMediaType())).toProtocolTreeNode())


        await self.toUpper(node)

    async def handleWhisperMessage(self, node) -> Any:
        encMessageProtocolEntity = EncryptedMessageProtocolEntity.fromProtocolTreeNode(node)

        enc = encMessageProtocolEntity.getEnc(EncProtocolEntity.TYPE_MSG)
        plaintext = self.manager.decrypt_msg(encMessageProtocolEntity.getAuthor(True), enc.getData(),
                                             enc.getVersion() == 2)

        if enc.getVersion() == 2:
            self.parseAndHandleMessageProto(encMessageProtocolEntity, plaintext)

        node = encMessageProtocolEntity.toProtocolTreeNode()
        node.addChild((ProtoProtocolEntity(plaintext, enc.getMediaType())).toProtocolTreeNode())

        await self.toUpper(node)

    async def handleSenderKeyMessage(self, node) -> Any:
        encMessageProtocolEntity = EncryptedMessageProtocolEntity.fromProtocolTreeNode(node)
        enc = encMessageProtocolEntity.getEnc(EncProtocolEntity.TYPE_SKMSG)

        try:
            plaintext = self.manager.group_decrypt(
                groupid=encMessageProtocolEntity.getFrom(True),
                participantid=encMessageProtocolEntity.getAuthor(True),
                data=enc.getData()
            )
            self.parseAndHandleMessageProto(encMessageProtocolEntity, plaintext)
            node = encMessageProtocolEntity.toProtocolTreeNode()
            node.addChild((ProtoProtocolEntity(plaintext, enc.getMediaType())).toProtocolTreeNode())
            await self.toUpper(node)
            return True
        except exceptions.NoSessionException:
            logger.warning("Got retry to {}, going to send a retry".format(encMessageProtocolEntity.getAuthor(False)))
            if node["id"] in self._retries and self._retries[node["id"]] >= 3:
                logger.warning("Too many retries for group msg from {}, giving up".format(encMessageProtocolEntity.getAuthor(False)))
                await self.toLower(OutgoingReceiptProtocolEntity(node["id"], node["from"], participant=node["participant"]).toProtocolTreeNode())
            else:
                await self.send_retry(node, self.manager.registration_id)
            return True  # handled — prevent fallback plain receipt in handleEncMessage

    def parseAndHandleMessageProto(self, encMessageProtocolEntity, serializedData) -> Any:
        m = Message()
        try:
            m.ParseFromString(serializedData)
        except Exception:
            logger.error("DUMP: {}".format(serializedData))
            logger.error("bytes: {}".format([s for s in serializedData]))
            raise
        if not m or not serializedData:
            raise exceptions.InvalidMessageException()

        if m.HasField("sender_key_distribution_message"):
            self.handleSenderKeyDistributionMessage(
                m.sender_key_distribution_message,
                encMessageProtocolEntity.getAuthor(True)
            )

    def handleSenderKeyDistributionMessage(self, senderKeyDistributionMessage, participantId) -> Any:
        groupId = senderKeyDistributionMessage.group_id
        self.manager.group_create_session(
            groupid=groupId,
            participantid=participantId,
            skmsgdata=senderKeyDistributionMessage.axolotl_sender_key_distribution_message
        )

    async def send_retry(self, message_node, registration_id, include_keys=False) -> Any:
        message_id = message_node["id"]
        if message_id in self._retries:
            count = self._retries[message_id]
            count += 1
        else:
            count = 1
        self._retries[message_id] = count
        # [salesquickly] SQ_RETRY_KEYS：和 baileys 一样，第 2 次起附带本地公钥包；
        # Invalid KeyId 说明对方用的公钥包本地没有，从第 1 次就附带。
        keys = None
        if include_keys or count >= 2:
            try:
                keys = self.manager.build_retry_keys()
            except Exception:  # noqa: BLE001
                logger.warning("[salesquickly] build retry keys failed, send retry without keys", exc_info=True)
        retry = RetryOutgoingReceiptProtocolEntity.fromMessageNode(message_node, registration_id, keys=keys)
        retry.count = count
        if keys:
            logger.info(
                "[salesquickly] retry receipt with keys: id={} to={} count={} prekey_id={} skey_id={}".format(
                    message_id, message_node["from"], count, keys["prekey_id"], keys["skey_id"]
                )
            )
        await self.toLower(retry.toProtocolTreeNode())

    def reset_retries(self, message_id) -> Any:
        if message_id in self._retries:
            del self._retries[message_id]
