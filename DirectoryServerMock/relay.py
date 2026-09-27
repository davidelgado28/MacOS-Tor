import asyncio
import struct
import base64
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

CELL_SIZE = 512
HEADER_SIZE = 14

class MacOnionRelay:
    def __init__(self, nickname: str, host: str, port: int, is_exit: bool = False):
        self.nickname = nickname
        self.host = host
        self.port = port
        self.is_exit = is_exit
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
    
        pub_bytes = self.public_key.public_bytes_raw()
        self.public_key_b64 = base64.b64encode(pub_bytes).decode('utf-8')
        
    def derive_session_key(self, client_ephemeral_pub_bytes: bytes) -> bytes:
        """Executa a troca de chaves X25519 e deriva a chave simétrica de 256 bits."""
        peer_pub = x25519.X25519PublicKey.from_public_bytes(client_ephemeral_pub_bytes)
        shared_secret = self.private_key.exchange(peer_pub)
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"MacOnionHKDFSalt",
            info=b"MacOnionSessionKey",
        )
        return hkdf.derive(shared_secret)

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer_addr = writer.get_extra_info('peername')
        print(f"[{self.nickname}] Nova conexão estabelecida de {peer_addr}")
        
        session_key = None
        
        try:
            while True:
                data = await reader.readexactly(CELL_SIZE)
                if not data:
                    break

                cmd, circuit_id, stream_id, payload_len = struct.unpack(">B II H 3x", data[:HEADER_SIZE])
                raw_payload = data[HEADER_SIZE:]
                
                print(f"[{self.nickname}] Célula recebida - Cmd: {cmd}, CircuitID: {circuit_id}")
                
                if cmd == 0x01:
                    ephemeral_pub_bytes = raw_payload[:32]
                    session_key = self.derive_session_key(ephemeral_pub_bytes)
                    print(f"[{self.nickname}] Handshake concluído. Chave de sessão derivada com sucesso.")
                    
                    response = struct.pack(">B II H 3x", 0x02, circuit_id, stream_id, 0) + b"\x00" * (CELL_SIZE - HEADER_SIZE)
                    writer.write(response)
                    await writer.drain()
                    
                elif cmd == 0x03:
                    if not session_key:
                        print(f"[{self.nickname}] Erro: Dados recebidos sem sessão estabelecida.")
                        break
                        
                    nonce = raw_payload[:12]
                    ciphertext = raw_payload[12:12 + payload_len + 16] 
                    
                    chacha = ChaCha20Poly1305(session_key)
                    decrypted_payload = chacha.decrypt(nonce, ciphertext, None)
                    
                    if self.is_exit:
                        print(f"[{self.nickname} - EXIT] Descriptografou última camada. Encaminhando para destino final.")
                    else:
                        print(f"[{self.nickname} - RELAY] Camada removida. Encaminhando para o próximo salto.")
                        
        except asyncio.IncompleteReadError:
            print(f"[{self.nickname}] Conexão encerrada pelo cliente.")
        except Exception as e:
            print(f"[{self.nickname}] Erro no processamento: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def start(self):
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        print(f"[{self.nickname}] Relay ativo em {self.host}:{self.port} (Public Key: {self.public_key_b64})")
        async with server:
            await server.serve_forever()

if __name__ == "__main__":
    relay = MacOnionRelay(nickname="GuardNode1", host="127.0.0.1", port=9001, is_exit=False)
    asyncio.run(relay.start())
