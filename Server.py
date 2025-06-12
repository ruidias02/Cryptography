import asyncio
import json
import os
import binascii
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509
from cryptography.x509.oid import NameOID



conn_port = 7777
clients = {}  # Armazena as instâncias de ServerWorker ativas
message_store = {}  # Dicionário global para armazenar as mensagens de cada cliente
message_directory = "C:\\Users\\Asus\\Desktop\\Mensagens"  # Diretório para armazenar os arquivos de mensagens
cert_directory = "C:\\Users\\Asus\\Desktop\\Mensagens\\Certificados"
os.makedirs(cert_directory, exist_ok=True)
# Cria o diretório de mensagens, se ele não existir
os.makedirs(message_directory, exist_ok=True)

class ServerWorker:

    def __init__(self, client_id):
        self.client_id = client_id
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())  # Gera chave privada
        self.shared_key = None  # Armazena a chave compartilhada
        self.load_messages()

    def create_certificate(self, server_id):
        cert_path = os.path.join(cert_directory, f"{server_id}_certificate.pem")
        private_key_path = os.path.join(cert_directory, f"{server_id}_private_key.pem")

        # Se o certificado já existe, lê e retorna seu conteúdo
        if os.path.exists(cert_path):
            with open(cert_path, "rb") as f:
                certificate_content = f.read()
                print(f"[Servidor] Certificado existente carregado de {cert_path}")
                return certificate_content
        
        # Se a chave privada já existe, carrega a chave para assinar o certificado
        if os.path.exists(private_key_path):
            with open(private_key_path, "rb") as f:
                private_key_content = f.read()
                signing_key = serialization.load_pem_private_key(private_key_content, password=None)
        else:
            # Cria uma nova chave privada e salva
            signing_key = ec.generate_private_key(ec.SECP256R1())
            with open(private_key_path, "wb") as f:
                f.write(signing_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            print(f"[Servidor] Nova chave privada gerada e salva em {private_key_path}")

        # Define os detalhes do certificado
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"Servidor_{server_id}"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MeuServidor"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
        ])

        # Gera o certificado X.509
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            signing_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            # Certificado válido por 1 ano
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).sign(signing_key, hashes.SHA256())

        # Salva o certificado
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print(f"[Servidor] Certificado criado e salvo em {cert_path}")

        return cert.public_bytes(serialization.Encoding.PEM)
    def get_public_key_hex(self):
        # Serializa a chave pública para o formato hexadecimal
        public_key_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        return public_key_bytes.hex()

    def derive_shared_key(self, client_public_key_hex):
        try:
            # Checa se o comprimento da string é par
            if len(client_public_key_hex) % 2 != 0:
                raise ValueError("Chave pública do cliente tem comprimento hexadecimal ímpar.")
            
            client_public_key_bytes = bytes.fromhex(client_public_key_hex)
            client_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_public_key_bytes)
            
            # Deriva a chave compartilhada usando a chave privada do servidor e a chave pública do cliente
            shared_key = self.private_key.exchange(ec.ECDH(), client_public_key)
        

            self.aes_key = HKDF(
                algorithm=hashes.SHA256(),
                length=16,  # 16 bytes = 128 bits para AES-128
                salt=None,
                info=b"AES encryption",
                backend=default_backend()
            ).derive(shared_key)
            print(f"[Servidor] Chave AES de 128 bits derivada (hex): {binascii.hexlify(self.aes_key).decode()}")
        
        except Exception as e:
            print(f"[Servidor] Erro ao derivar chave compartilhada: {e}")

            
            print(f"[Servidor] Chave simétrica compartilhada derivada (hex): {binascii.hexlify(self.shared_key).decode()}")
        
        except Exception as e:
            print(f"[Servidor] Erro ao derivar chave compartilhada: {e}")

    def encrypt_message_content(self, recipient, subject, content):
        try:
            # Concatena destinatário, assunto e conteúdo como uma única string para encriptar
            full_content = f"{recipient}|{subject}|{content}"
            content_bytes = full_content.encode()
            nonce = os.urandom(12)  # Gera um nonce de 12 bytes
            aesgcm = AESGCM(self.aes_key)
            
            # Encripta todo o conteúdo concatenado
            encrypted_content = aesgcm.encrypt(nonce, content_bytes, None)
            
            # Retorna o nonce + conteúdo criptografado em hexadecimal
            encrypted_message_hex = binascii.hexlify(nonce + encrypted_content).decode()
            if len(encrypted_message_hex) % 2 != 0:
                print("[Servidor] Erro: string criptografada com comprimento hexadecimal ímpar.")
            return encrypted_message_hex
        except Exception as e:
            print(f"[Servidor] Erro ao encriptar conteúdo da mensagem: {e}")
            return None

    def decrypt_message(self, encrypted_message_hex):
        try:
            if len(encrypted_message_hex) % 2 != 0:
                print(f"[Servidor] Erro ao desencriptar mensagem: string hexadecimal de comprimento ímpar ({encrypted_message_hex})")
                return None

            encrypted_message = binascii.unhexlify(encrypted_message_hex)
            nonce = encrypted_message[:12]
            ciphertext = encrypted_message[12:]
            aesgcm = AESGCM(self.aes_key)
            decrypted_content = aesgcm.decrypt(nonce, ciphertext, None).decode()

            # Divide o conteúdo desencriptado para obter destinatário, assunto e conteúdo
            recipient, subject, content, timestamp = decrypted_content.split('|', 3)
            return recipient, subject, content, timestamp  # Retorna todos os valores separadamente
            
        except Exception as e:
            print(f"[Servidor] Erro ao desencriptar mensagem: {e}")
            return None

    def generate_keys(self):
        """Gera o par de chaves ECC e exibe a chave pública e privada."""
        self.private_key = ec.generate_private_key(ec.SECP256R1())  # Gera a chave privada ECC
        self.public_key = self.private_key.public_key()  # Obtém a chave pública correspondente
        print(f"[Servidor] Chave privada para {self.client_id} (hex): {self.private_key.private_numbers().private_value:x}")
        print(f"[Servidor] Chave pública para {self.client_id} (hex): {self.public_key.public_numbers().x:x}{self.public_key.public_numbers().y:x}\n")

    def set_client_public_key(self, public_key_bytes):
        """Define a chave pública do cliente."""
        self.client_public_key = serialization.load_pem_public_key(public_key_bytes)
        print(f"[Servidor] Chave pública do cliente {self.client_id} recebida e armazenada.")
        

    def load_messages(self):
        """Carrega as mensagens do cliente do arquivo para o dicionário global."""
        filename = os.path.join(message_directory, f"{self.client_id}.json")
        if os.path.exists(filename):
            with open(filename, "r") as f:
                message_store[self.client_id] = json.load(f)
        else:
            message_store[self.client_id] = []

    def save_messages(self):
        """Salva as mensagens do cliente no arquivo."""
        filename = os.path.join(message_directory, f"{self.client_id}.json")
        with open(filename, "w") as f:
            json.dump(message_store[self.client_id], f)

    def store_message(self, recipient_id, message):
        """Armazena a mensagem para o destinatário especificado, independentemente de ele estar online."""
        # Se o destinatário não tiver mensagens pré-existentes, inicialize uma lista para ele
        if recipient_id not in message_store:
            message_store[recipient_id] = []
        
        message['lida'] = False  # Marca a mensagem como não lida
        message_store[recipient_id].append(message)
        
        # Salva as mensagens no arquivo correspondente do destinatário
        filename = os.path.join(message_directory, f"{recipient_id}.json")
        with open(filename, "w") as f:
            json.dump(message_store[recipient_id], f)
        
        return True

    def delete_message(self, message_id):
        """Remove a mensagem com o ID especificado do armazenamento persistente."""
        for i, msg in enumerate(message_store[self.client_id]):
            if msg["id_msg"] == message_id:
                del message_store[self.client_id][i]
                self.save_messages()  # Atualiza o arquivo após a exclusão
                return True
        return False
    
    def sign_client_certificate(self, client_certificate_bytes):
        try:
            # Carrega o certificado do cliente
            client_certificate = x509.load_pem_x509_certificate(client_certificate_bytes, default_backend())
            
            # Gera um novo certificado assinado pelo servidor
            subject = client_certificate.subject
            issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "MeuServidor"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Autoridade Certificadora Local"),
                x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
            ])
            
            signed_cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                client_certificate.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=365)
            ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            ).sign(self.private_key, hashes.SHA256())
            
            print(f"[Servidor] Certificado do cliente assinado com sucesso.")
            return signed_cert.public_bytes(serialization.Encoding.PEM)
        except Exception as e:
            print(f"[Servidor] Certificado não recebido")
            return None

async def handle_client(reader, writer):
    client_id = (await reader.readline()).decode().strip()
    clients[client_id] = ServerWorker(client_id)

    # Recebe a chave pública do cliente
    data = await reader.readline()
    client_public_key_hex = data.decode().strip()
    print(f"[Servidor] Chave pública recebida do cliente {client_id} (hex): {client_public_key_hex}")
    
    # Envia a chave pública do servidor ao cliente
    server_public_key_hex = clients[client_id].get_public_key_hex()
    writer.write((server_public_key_hex + '\n').encode())
    await writer.drain()
    print(f"[Servidor] Chave pública enviada ao cliente '{client_id}'.")

    certificate_bytes = b''
    while True:
        line = await reader.readline()
        if line.strip() == b'':  # Se o cliente envia uma linha em branco
            writer.write(b'\n')  # O servidor responde com uma linha em branco
            await writer.drain()
            print("[Servidor] Linha em branco recebida e respondida com linha em branco.")
            break
        certificate_bytes += line  # Acumula o conteúdo do certificado

    # Aqui você já tem o certificado completo
    print("[Servidor] Conteúdo completo do Certificado:")
    print(certificate_bytes.decode('utf-8'))

    signed_certificate = clients[client_id].sign_client_certificate(certificate_bytes)

    if signed_certificate:
        # Envia o certificado assinado ao cliente de uma vez só
        writer.write(signed_certificate + b'\n')  # Certificado assinado como uma única resposta
        await writer.drain()
        print(f"[Servidor] Certificado do cliente {client_id} assinado e enviado.")
    else:
        print(f"[Servidor] Falha ao assinar o certificado do cliente {client_id}.")
        # Deriva a chave compartilhada e a chave AES
    clients[client_id].derive_shared_key(client_public_key_hex)
    while True:
        data = await reader.readline()
        if not data:
            break
        message = data.decode().strip()

        if message.startswith("enviar"):
            await handle_enviar(message, client_id, writer)
        elif message.startswith("consultar_todas"):
            await handle_consultar_todas(client_id, writer)
        elif message.startswith("consultar_novas"):
            await handle_consultar_novas(client_id, writer)
        elif message.startswith("ler_"):
            await handle_ler(message, client_id, writer)
        elif message.startswith("apagar_"):
            await handle_apagar(message, client_id, writer)

    del clients[client_id]
    writer.close()

async def handle_enviar(message, sender_id, writer):
    msg_data = json.loads(message.split(' ', 1)[1])
    encrypted_content = msg_data["conteudo"]
    assinatura = msg_data.get("assinatura")

    print(f"[Servidor] Assinatura recebida para armazenamento: {assinatura}")

    # Descriptografa a mensagem inteira (todos os campos: destinatário, assunto, conteúdo)
    try:
        decrypted_recipient, decrypted_subject, decrypted_content, decrypted_timestamp = clients[sender_id].decrypt_message(encrypted_content)
        if decrypted_recipient is None:
            raise ValueError("Falha na descriptografia da mensagem.")

        # Organiza a mensagem para armazenamento
        mensagem = {
            "id_msg": len(message_store.get(decrypted_recipient, [])) + 1,
            "id_origem": sender_id,
            "id_destinatario": decrypted_recipient,
            "assunto": decrypted_subject,
            "conteudo": decrypted_content,
            "assinatura": assinatura,
            "timestamp": decrypted_timestamp,
            "lida": False
        }

        print(f"[Servidor] Mensagem armazenada com assinatura: {mensagem['assinatura']} e conteúdo descriptografado: {mensagem['conteudo']}")

        # Armazena a mensagem e envia resposta ao cliente
        if clients[sender_id].store_message(decrypted_recipient, mensagem):
            writer.write(json.dumps({"status": "Mensagem enviada com sucesso.", "id_msg": mensagem["id_msg"]}).encode() + b'\n')
        else:
            writer.write(json.dumps({"error": f"Erro ao armazenar a mensagem."}).encode() + b'\n')
    except Exception as e:
        writer.write(json.dumps({"error": f"Erro ao descriptografar a mensagem: {e}"}).encode() + b'\n')
    await writer.drain()

async def handle_consultar_todas(client_id, writer):
    clients[client_id].load_messages()
    client_messages = message_store.get(client_id, [])
    if client_messages:
        mensagens_encrypt = []
        for msg in client_messages:
            try:
                msg_encrypt = msg.copy()  # Cria uma cópia da mensagem
                # Criptografa o conteúdo passando os parâmetros corretos
                msg_encrypt["conteudo"] = clients[client_id].encrypt_message_content(
                    msg["id_destinatario"], msg["assunto"], msg["conteudo"]
                )
                msg_encrypt["assinatura"] = msg["assinatura"]
                mensagens_encrypt.append(msg_encrypt)

                msg["lida"] = True  # Marca como lida no armazenamento
            except Exception as e:
                print(f"[Servidor] Erro ao criptografar conteúdo da mensagem ID {msg['id_msg']}: {e}")

        clients[client_id].save_messages()  # Salva o estado de leitura no arquivo
        writer.write((json.dumps({"mensagens": mensagens_encrypt}) + '\n').encode())
    else:
        writer.write(json.dumps({"info": "Não há mensagens."}).encode() + b'\n')
    await writer.drain()
    
async def handle_consultar_novas(client_id, writer):
    clients[client_id].load_messages()
    novas_mensagens = [msg for msg in message_store.get(client_id, []) if not msg["lida"]]
    if novas_mensagens:
        mensagens_encrypt = []
        for msg in novas_mensagens:
            try:
                msg_encrypt = msg.copy()  # Cria uma cópia da mensagem
                # Criptografa o conteúdo passando os parâmetros corretos
                msg_encrypt["conteudo"] = clients[client_id].encrypt_message_content(
                    msg["id_destinatario"], msg["assunto"], msg["conteudo"]
                )
                msg_encrypt["assinatura"] = msg["assinatura"]
                mensagens_encrypt.append(msg_encrypt)
                msg["lida"] = True  # Marca como lida no armazenamento
            except Exception as e:
                print(f"[Servidor] Erro ao criptografar conteúdo da mensagem ID {msg['id_msg']}: {e}")

        clients[client_id].save_messages()  # Salva o estado de leitura no arquivo
        writer.write((json.dumps({"mensagens": mensagens_encrypt}) + '\n').encode())
    else:
        writer.write(json.dumps({"info": "Não há novas mensagens não lidas."}).encode() + b'\n')
    await writer.drain()
    
async def handle_ler(message, client_id, writer):
    clients[client_id].load_messages()
    id_msg = int(message.split('_', 1)[1])
    mensagem = next((msg for msg in message_store.get(client_id, []) if msg["id_msg"] == id_msg), None)

    if mensagem:
        mensagem["lida"] = True
        clients[client_id].save_messages()  # Salva o estado de leitura no arquivo

        # Cria uma cópia da mensagem para criptografar o conteúdo
        msg_encrypt = mensagem.copy()
        try:
            # Criptografa apenas o conteúdo da mensagem
            msg_encrypt["conteudo"] = clients[client_id].encrypt_message_content(
    mensagem["id_destinatario"], mensagem["assunto"], mensagem["conteudo"]
)
            msg_encrypt["assinatura"] = mensagem["assinatura"]
            # Envia a resposta JSON com o conteúdo criptografado
            writer.write((json.dumps(msg_encrypt) + '\n').encode())
        except Exception as e:
            print(f"[Servidor] Erro ao criptografar conteúdo da mensagem ID {id_msg}: {e}")
            writer.write(json.dumps({"error": f"Erro ao criptografar a mensagem ID {id_msg}: {e}"}).encode() + b'\n')
    else:
        writer.write(json.dumps({"error": f"Mensagem com ID {id_msg} não encontrada."}).encode() + b'\n')
    await writer.drain()


async def handle_apagar(message, client_id, writer):
    id_msg = int(message.split('_', 1)[1])
    if clients[client_id].delete_message(id_msg):
        writer.write(json.dumps({"status": f"Mensagem com ID {id_msg} apagada com sucesso."}).encode() + b'\n')
    else:
        writer.write(json.dumps({"error": f"Mensagem com ID {id_msg} não encontrada."}).encode() + b'\n')
    await writer.drain()

def run_server():
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_client, '0.0.0.0', conn_port)
    server = loop.run_until_complete(coro)
    print('Servidor rodando em {}'.format(server.sockets[0].getsockname()))
    worker = ServerWorker(client_id="server")
    worker.cert_directory = cert_directory
    server_cert = worker.create_certificate("server")
    try:
        loop.run_forever()
    finally:
        server.close()
        loop.run_until_complete(server.wait_closed())
        loop.close()

if __name__ == '__main__':
    run_server()
