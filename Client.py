import asyncio
import json
import os
import binascii
import datetime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, BestAvailableEncryption
from cryptography import x509
from cryptography.x509.oid import NameOID

conn_port = 7777
message_directory = "C:\\Users\\Asus\\Desktop\\Mensagens"  # Diretório para armazenar os arquivos de mensagens
cert_directory = "C:\\Users\\Asus\\Desktop\\Mensagens\\Certificados"


class Client:
    def __init__(self, client_id):
        self.client_id = client_id
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())  # Gera chave privada
        self.shared_key = None  # Armazena a chave compartilhada

        self.signing_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        cert_path = os.path.join(cert_directory, f"{client_id}_certificate.pem")
        certificate_exists = os.path.exists(cert_path)
        
        self.certificate_sent = certificate_exists  # Define baseado na existência do certificado

        self.signing_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        
        # Garante que o diretório existe
        if not os.path.exists(cert_directory):
            os.makedirs(cert_directory)
        
        self.load_or_create_signing_key()
        self.certificate = self.create_certificate()  # Adicione esta linha para armazenar o certificado
    def get_public_key_hex(self):
        # Serializa a chave pública para o formato hexadecimal
        public_key_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        return public_key_bytes.hex()

    def derive_shared_key(self, server_public_key_hex):
        try:
            # Converte a chave pública recebida do servidor para o formato de chave pública de curvas elípticas
            server_public_key_bytes = bytes.fromhex(server_public_key_hex)
            server_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), server_public_key_bytes)
            
            # Deriva a chave compartilhada usando a chave privada do cliente e a chave pública do servidor
            shared_key = self.private_key.exchange(ec.ECDH(), server_public_key)

            # Deriva a chave AES de 128 bits (16 bytes) usando HKDF
            self.aes_key = HKDF(
                algorithm=hashes.SHA256(),
                length=16,  # 16 bytes = 128 bits para AES-128
                salt=None,
                info=b"AES encryption",
                backend=default_backend()
            ).derive(shared_key)

            print(f"[Cliente] Chave AES de 128 bits derivada (hex): {binascii.hexlify(self.aes_key).decode()}")
        
        except Exception as e:
            print(f"[Cliente] Erro ao derivar chave compartilhada: {e}")
    def set_server_public_key(self, public_key_bytes):
        """Define a chave pública do servidor."""
        self.server_public_key = serialization.load_pem_public_key(public_key_bytes)
        print(f"[Cliente] Chave pública do servidor recebida e armazenada.")

    def encrypt_message_content(self, recipient, subject, content, timestamp):
        try:
            # Concatena destinatário, assunto e conteúdo como uma única string para encriptar
            full_content = f"{recipient}|{subject}|{content}|{timestamp}"
            content_bytes = full_content.encode()
            nonce = os.urandom(12)  # Gera um nonce de 12 bytes
            aesgcm = AESGCM(self.aes_key)
            
            # Encripta todo o conteúdo concatenado
            encrypted_content = aesgcm.encrypt(nonce, content_bytes, None)
            
            # Retorna o nonce + conteúdo criptografado em hexadecimal
            encrypted_message_hex = binascii.hexlify(nonce + encrypted_content).decode()
            if len(encrypted_message_hex) % 2 != 0:
                print("[Cliente] Erro: string criptografada com comprimento hexadecimal ímpar.")
            return encrypted_message_hex
        except Exception as e:
            print(f"[Cliente] Erro ao encriptar conteúdo da mensagem: {e}")
            return None
        
    def decrypt_message(self, encrypted_message_hex):
        try:
            if len(encrypted_message_hex) % 2 != 0:
                print(f"[Cliente] Erro ao desencriptar mensagem: string hexadecimal de comprimento ímpar ({encrypted_message_hex})")
                return None

            encrypted_message = binascii.unhexlify(encrypted_message_hex)
            nonce = encrypted_message[:12]
            ciphertext = encrypted_message[12:]
            aesgcm = AESGCM(self.aes_key)
            decrypted_content = aesgcm.decrypt(nonce, ciphertext, None).decode()

            # Divide o conteúdo desencriptado para obter destinatário, assunto e conteúdo
            recipient, subject, content = decrypted_content.split('|', 2)
            
            # Aqui está o ajuste, você pode apenas retornar o conteúdo:
            return content  # Agora a função retorna apenas o conteúdo
            
        except Exception as e:
            print(f"[Cliente] Erro ao desencriptar mensagem: {e}")
            return None
        
    def load_or_create_signing_key(self):
        private_key_path = os.path.join(cert_directory, f"{self.client_id}_signing_key.pem")
        
        if not os.path.exists(private_key_path):
            # A chave privada não existe, então criamos uma nova e pedimos uma senha para protegê-la
            password = input("Digite uma senha para proteger a chave privada de assinatura: ").encode()
            
            with open(private_key_path, "wb") as f:
                f.write(self.signing_key.private_bytes(
                    Encoding.PEM,
                    PrivateFormat.PKCS8,
                    encryption_algorithm=BestAvailableEncryption(password)
                ))
            print(f"[Cliente] Chave privada de assinatura salva em {private_key_path}")
        else:
            # A chave privada já existe, pede a senha cada vez que precisa ser acessada
            self.load_signing_key_with_password()

    def create_certificate(self):
        cert_path = os.path.join(cert_directory, f"{self.client_id}_certificate.pem")
        
        # Verifica se o certificado já existia antes da execução
        if os.path.exists(cert_path):
            with open(cert_path, "rb") as f:
                certificate_content = f.read()
                print(f"[Cliente] Certificado existente carregado de {cert_path}")
                return certificate_content
        
        # Se não existia, cria o certificado
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.client_id)])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.signing_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            # Certificado válido por um ano
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).sign(self.signing_key, hashes.SHA256(), default_backend())
        
        # Salva o certificado no disco
        certificate_content = cert.public_bytes(Encoding.PEM)
        with open(cert_path, "wb") as f:
            f.write(certificate_content)
        
        print(f"[Cliente] Certificado salvo em {cert_path}")
        return certificate_content
    
    def sign_message(self, recipient_id, subject, content, timestamp):
        """
        Assina uma mensagem usando a chave privada do cliente
        """
        try:
            # Carrega a chave de assinatura com senha primeiro
            self.load_signing_key_with_password()
            
            # Concatena os dados da mensagem da mesma forma que será verificada
            message_data = f"{recipient_id}{subject}{content}{timestamp}"
            message_bytes = message_data.encode()
            
            # Assina a mensagem
            signature = self.signing_key.sign(
                message_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            return binascii.hexlify(signature).decode()
        except Exception as e:
            print(f"[Cliente] Erro ao assinar mensagem: {e}")
            return None
    def load_signing_key_with_password(self):
        """Carrega a chave privada de assinatura pedindo a senha ao usuário."""
        private_key_path = os.path.join(cert_directory, f"{self.client_id}_signing_key.pem")
        
        # Tenta duas vezes para carregar a chave privada com a senha
        for attempt in range(2):
            password = input("Digite a senha para acessar a chave privada de assinatura: ").encode()
            try:
                with open(private_key_path, "rb") as f:
                    self.signing_key = serialization.load_pem_private_key(
                        f.read(),
                        password=password,
                        backend=default_backend()
                    )
                print(f"[Cliente] Chave privada de assinatura carregada com sucesso.")
                return  # Saída do método se a senha estiver correta
            except Exception as e:
                print(f"[Cliente] Erro ao carregar a chave privada de assinatura: {e}")
                if attempt == 0:
                    print("[Cliente] Tente novamente.")
        
        # Se as duas tentativas falharem, encerra o programa
        print("[Cliente] Senha incorreta. O programa será encerrado.")
        exit(1)
            

    def load_public_key(self, client_id):
        """Carrega a chave pública de um cliente armazenada no diretório de certificados."""
        public_key_path = os.path.join(cert_directory, f"{client_id}_certificate.pem")
        if not os.path.exists(public_key_path):
            print(f"[Cliente] Chave pública do cliente {client_id} não encontrada.")
            return None

        # Carrega o certificado e extrai a chave pública
        with open(public_key_path, "rb") as f:
            cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            # Convertendo para o formato correto (EllipticCurvePublicKey)
            public_key = cert.public_key()
            if isinstance(public_key, ec.EllipticCurvePublicKey):
                return public_key
            else:
                print(f"[Cliente] A chave pública não é do tipo esperado: {type(public_key)}")
                return None

    def verify_signature_from_file(self, recipient_id, subject, content, timestamp, signature_hex, sender_id):
        """
        Verifica a assinatura de uma mensagem usando a chave pública do remetente
        """
        public_key = self.load_public_key(sender_id)
        if public_key is None:
            print(f"[Cliente] Não foi possível carregar a chave pública do remetente {sender_id}.")
            return False

        try:
            # Recria a mensagem original da mesma forma que foi assinada
            message_data = f"{recipient_id}{subject}{content}{timestamp}"
            
            # Converte a assinatura de hexadecimal para bytes
            signature = binascii.unhexlify(signature_hex)
            message_bytes = message_data.encode()
            
            # Verifica a assinatura
            public_key.verify(
                signature,
                message_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception as e:
            return False

    
    # Verifica a assinatura com a chave pública fornecida


    def verify_signature(self, public_key_obj, message, signature_hex):
        try:
            # Converte a assinatura de hexadecimal para bytes
            signature = binascii.unhexlify(signature_hex)
            message_bytes = message.encode()  # Converte a mensagem para bytes
            
            # Verifica a assinatura com a chave pública
            if isinstance(public_key_obj, ec.EllipticCurvePublicKey):
                public_key_obj.verify(
                    signature,
                    message_bytes,
                    ec.ECDSA(hashes.SHA256())
                )
                print("[Cliente] Assinatura verificada com sucesso!")
                return True
            else:
                print("[Cliente] A chave pública fornecida não é uma EllipticCurvePublicKey.")
                return False
        except Exception as e:
            print(f"[Cliente] Erro na verificação da assinatura: {e}")
            return False

async def handle_server_messages(reader, client, ):
    while True:
        try:
            data = await reader.readline()
            if not data:
                break

            message = data.decode().strip()
            msg_json = json.loads(message)
            
            if 'mensagens' in msg_json:
                mensagens = msg_json['mensagens']
                if mensagens:
                    print("\n[Servidor] Lista de Mensagens:")
                    for msg in mensagens:
                        status = "Lida" if msg['lida'] else "Não Lida"
                        print(f"ID da Mensagem: {msg['id_msg']}")
                        print(f"De: {msg['id_origem']}")
                        print(f"Assunto: {msg['assunto']}")
                        
                        # Desencripta a mensagem
                        decrypted_content = client.decrypt_message(msg['conteudo'])
                        if decrypted_content:
                            print(f"Conteúdo: {decrypted_content}")
                            
                            # Verifica a assinatura
                            is_signature_valid = client.verify_signature_from_file(
                                msg['id_destinatario'],
                                msg['assunto'],
                                decrypted_content,
                                msg['timestamp'],  # Use o timestamp da mensagem
                                msg['assinatura'],
                                msg['id_origem']
                            )
                        print(f"Timestamp: {msg['timestamp']}")
                        print(f"Status: {status}")
                        print(f"Status da Assinatura: {'Válida' if is_signature_valid else 'Inválida'}")
                        print("-" * 40)
                else:
                    print("\n[Servidor] Não há mensagens para exibir.")
            elif 'info' in msg_json:
                print(f"\n[Servidor] {msg_json['info']}")
            elif 'error' in msg_json:
                print(f"\n[Servidor] Erro: {msg_json['error']}")
            elif 'status' in msg_json:
                if 'id_msg' in msg_json:
                    print(f"\n[Servidor] {msg_json['status']} (ID da Mensagem: {msg_json['id_msg']})")
                else:
                    print(f"\n[Servidor] {msg_json['status']}")
            else:
                # Tratamento de mensagens específicas (detalhe de uma mensagem)
                if 'conteudo' in msg_json:
                    print("\n[Servidor] Detalhes da Mensagem:")
                    print(f"ID da Mensagem: {msg_json.get('id_msg', 'N/A')}")
                    print(f"De: {msg_json['id_origem']}")
                    print(f"Para: {msg_json['id_destinatario']}")
                    print(f"Assunto: {msg_json['assunto']}")
                    decrypted_content = client.decrypt_message(msg_json['conteudo'])
                    print(f"Conteúdo: {decrypted_content}")  # Conteúdo agora é desencriptado

                    # Verificação da assinatura após a decriptação
                    is_signature_valid = client.verify_signature_from_file(
                                msg['id_destinatario'],
                                msg['assunto'],
                                decrypted_content,
                                msg['timestamp'],  # Use o timestamp da mensagem
                                msg['assinatura'],
                                msg['id_origem']
                            )
                    print(f"Timestamp: {msg_json['timestamp']}")
                    print(f"Status da Assinatura: {'Válida' if is_signature_valid else 'Inválida'}")
                    print("-" * 40)
        except json.JSONDecodeError:
            print(f"\n[Servidor] {message}")

async def consultar_ficheiro_alheio(writer, client_id):
    loop = asyncio.get_event_loop()
    other_client_id = await loop.run_in_executor(None, input, "Digite o ID do cliente cujo arquivo deseja acessar: ")
    other_client_id = other_client_id.strip()

    if not other_client_id:
        print("[Cliente] ID do cliente não pode ser vazio.")
        return

    # Permite o acesso se o other_client_id for igual ao próprio client_id
    if other_client_id != client_id:
        print("[Cliente] Acesso negado. Você não pode consultar o arquivo de outro cliente.")
        return

    file_path = os.path.join(message_directory, f"{other_client_id}.json")

    try:
        with open(file_path, "r") as f:
            messages = json.load(f)
            print(f"\n[Cliente] Mensagens do cliente '{other_client_id}':")
            for msg in messages:
                print(f"ID da Mensagem: {msg['id_msg']}")
                print(f"De: {msg['id_origem']}")
                print(f"Assunto: {msg['assunto']}")
                print(f"Conteúdo: {msg['conteudo']}")
                print(f"Timestamp: {msg['timestamp']}")
                print(f"Status: {'Lida' if msg['lida'] else 'Não Lida'}")
                print("-" * 40)
    except FileNotFoundError:
        print(f"[Cliente] Arquivo para o cliente '{other_client_id}' não encontrado.")
    except json.JSONDecodeError:
        print(f"[Cliente] Erro ao decodificar o JSON do arquivo de '{other_client_id}'.")
        
async def user_input(writer, client):
    loop = asyncio.get_event_loop()
    while True:
        print("\nOpções:")
        print("1. Enviar mensagem")
        print("2. Consultar todas as mensagens")
        print("3. Consultar novas mensagens")
        print("4. Ler uma mensagem específica")
        print("5. Apagar uma mensagem específica")
        print("6. Sair")
        print("7. Consultar arquivo de outro cliente")

        raw_choice = await loop.run_in_executor(None, input, "Escolha uma opção (1/2/3/4/5/6/7): ")
        choice = raw_choice.strip()

        if choice == '1':
            recipient = await loop.run_in_executor(None, input, "Digite o ID do destinatário: ")
            recipient = recipient.strip()
            if not recipient:
                print("[Cliente] Destinatário não pode ser vazio.")
                continue
            subject = await loop.run_in_executor(None, input, "Digite o assunto (max 50 caracteres): ")
            subject = subject.strip()
            if len(subject) > 50:
                print("[Cliente] Assunto excede 50 caracteres. Tente novamente.")
                continue
            content = await loop.run_in_executor(None, input, "Digite a mensagem: ")
            content = content.strip()
            if not content:
                print("[Cliente] Mensagem não pode ser vazia.")
                continue
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

            # Encrypt the message
            signature = client.sign_message(recipient, subject, content, timestamp)
            encrypted_content = client.encrypt_message_content(recipient, subject, content, timestamp)
            if encrypted_content is None:
                print("[Cliente] Erro ao encriptar a mensagem.")
                continue

            print(f"[Cliente] Conteúdo encriptado: {encrypted_content}")  # Debug print
            
            enviar_comando = f'enviar {json.dumps({"conteudo": encrypted_content, "assinatura": signature})}\n'.encode()
            writer.write(enviar_comando)
            await writer.drain()
            print(f"[Cliente] Mensagem enviada para '{recipient}'.")
            
        elif choice == '2':
            writer.write(b'consultar_todas\n')
            await writer.drain()
            print("[Cliente] Comando 'consultar_todas' enviado.")
        elif choice == '3':
            writer.write(b'consultar_novas\n')
            await writer.drain()
            print("[Cliente] Comando 'consultar_novas' enviado.")
        elif choice == '4':
            id_msg_input = await loop.run_in_executor(None, input, "Digite o ID da mensagem que deseja ler: ")
            id_msg = id_msg_input.strip()
            if not id_msg.isdigit():
                print("[Cliente] ID da mensagem inválido. Deve ser um número inteiro.")
                continue
            ler_comando = f'ler_{id_msg}\n'.encode()
            writer.write(ler_comando)
            await writer.drain()
            print(f"[Cliente] Comando 'ler_{id_msg}' enviado.")
        elif choice == '5':
            id_msg_input = await loop.run_in_executor(None, input, "Digite o ID da mensagem que deseja apagar: ")
            id_msg = id_msg_input.strip()
            if not id_msg.isdigit():
                print("[Cliente] ID da mensagem inválido. Deve ser um número inteiro.")
                continue
            apagar_comando = f'apagar_{id_msg}\n'.encode()
            writer.write(apagar_comando)
            await writer.drain()
            print(f"[Cliente] Comando 'apagar_{id_msg}' enviado.")
        elif choice == '6':
            print("Encerrando conexão.")
            writer.close()
            await writer.wait_closed()
            break

        elif choice == '7':
            await consultar_ficheiro_alheio(writer, client.client_id)  # Passa writer e client_id

        else:
            print("[Cliente] Opção inválida. Tente novamente.")

async def tcp_client(client_id):
    try:
        reader, writer = await asyncio.open_connection('127.0.0.1', conn_port)
    except ConnectionRefusedError:
        print("[Cliente] Não foi possível conectar ao servidor.")
        return

    client = Client(client_id)

    # Envia o ID do cliente ao servidor
    writer.write((client_id + '\n').encode())
    await writer.drain()

    # Envia a chave pública do cliente ao servidor
    client_public_key_hex = client.get_public_key_hex()
    writer.write((client_public_key_hex + '\n').encode())
    await writer.drain()
    print(f"[Cliente] Chave pública enviada ao servidor: {client_public_key_hex}")

    # Continuar lendo a chave pública
    server_public_key_hex = (await reader.readline()).decode().strip()
    print(f"[Cliente] Chave pública recebida do servidor (hex): {server_public_key_hex}")
    
    # Deriva a chave compartilhada e a chave AES
    client.derive_shared_key(server_public_key_hex)

    if not client.certificate_sent:
        writer.write(client.certificate + b'\n')
        await writer.drain()
        client.certificate_sent = True
        print("[Cliente] Certificado enviado ao servidor.")
    else:
        writer.write(b'\n')
        await writer.drain()

    certificate_bytes = b''
    certificate_started = False

    while True:
        line = await reader.readline()
        if b"BEGIN CERTIFICATE" in line:
            certificate_started = True
        if certificate_started:
            certificate_bytes += line
        if b"END CERTIFICATE" in line:
            break
        if not certificate_started and line.strip() == b"":
            print("[Cliente] Linha em branco recebida. Sem certificado a processar.")
            break

    print("[Servidor] Certificado completo recebido:")
    print(certificate_bytes.decode('utf-8'))
        # Caso nenhuma parte do certificado tenha começado, trate linhas inesperadas
    if not certificate_started and line.strip() == b"":
            print("[Cliente] Linha inesperada recebida antes do início do certificado.")

            if certificate_bytes:
                # Aqui, certificate_bytes contém o certificado completo enviado pelo servidor
                print(f"[Cliente] Certificado do servidor recebido:\n{certificate_bytes.decode()}")

                # Salvar o certificado em um arquivo
                cert_path = os.path.join(cert_directory, f"{client_id}_certificate.pem")  # ou outro nome apropriado
                with open(cert_path, "wb") as cert_file:
                    cert_file.write(certificate_bytes)
                print(f"[Cliente] Certificado do servidor armazenado em {cert_path}")
            else:
                print("[Cliente] Nenhum certificado recebido do servidor.")

    # Continua com as outras operações de cliente...
    await asyncio.gather(handle_server_messages(reader,client), user_input(writer, client))

def run_client():
    client_id = input("Digite seu ID de cliente: ").strip()
    if not client_id:
        print("[Cliente] ID de cliente não pode ser vazio.")
        return
    asyncio.run(tcp_client(client_id))

if __name__ == '__main__':
    run_client()


