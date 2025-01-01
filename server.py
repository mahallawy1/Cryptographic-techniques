import socket
import pickle
from crypto.AsymmetricCipher import RSA
from KeyManagement import KeyManager
from crypto.SymmetricCipher import Encryptor, AESEncryption, DESEncryption
from Authenticate import Authenticator

class Server:
    def __init__(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = socket.gethostname()
        self.port = 12345
        self.session_key = None
        self.session_iv = None
        self.session_encryptor = None
        self.auth = Authenticator()

    def server_up(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(10)
        print(f"Server is listening on {self.host}:{self.port}...")

        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"Got connection from client at: {addr}")
            
            try:
                # Generate public/private key pair and send public key to client
                key_manager = KeyManager()
                public_key_pem, private_key_pem = key_manager.get_key_pair("server")
                rsa = RSA()
                private_key = key_manager.pem_to_rsa_private_key(private_key_pem)
                client_socket.send(pickle.dumps({"public_key": public_key_pem}))
                print("Sent public key to the client.")

                # Receive session key and encryption mode from client
                data = client_socket.recv(4096)
                if not data:
                    print("Error: No data received from client.")
                    client_socket.close()
                    continue

                try:
                    received_dict = pickle.loads(data)
                    print(f"Received encrypted dictionary: {received_dict}")

                    if "mode" not in received_dict:
                        print("Error: 'mode' key missing in received data.")
                        client_socket.close()
                        continue

                    # Decrypt session information
                    received_dict["mode"] = rsa.decrypt(received_dict["mode"], private_key).decode()
                    self.session_key = rsa.decrypt(received_dict["key"], private_key)
                    self.session_iv = rsa.decrypt(received_dict["iv"], private_key)
                    print("Decrypted session data:", received_dict)

                    # Set session encryptor based on mode
                    if received_dict["mode"][:3] == "AES":
                        self.session_encryptor = Encryptor(AESEncryption())
                    elif received_dict["mode"][:3] == "DES":
                        self.session_encryptor = Encryptor(DESEncryption())
                    print("Handshake complete. Awaiting client requests.")
                except Exception as e:
                    print(f"Error during handshake: {e}")
                    client_socket.close()
                    continue

                # Process client requests
                while True:
                    data = client_socket.recv(4096)
                    if not data:
                        print("No more data from client. Closing connection.")
                        break

                    try:
                        encrypted_request = pickle.loads(data)
                        decrypted_request = {
                            "mode": self.session_encryptor.decrypt_text(encrypted_request["mode"], self.session_key, self.session_iv).decode(),
                            "username": self.session_encryptor.decrypt_text(encrypted_request["username"], self.session_key, self.session_iv).decode(),
                            "password": self.session_encryptor.decrypt_text(encrypted_request["password"], self.session_key, self.session_iv).decode(),
                        }
                        print(f"Decrypted request: {decrypted_request}")

                        if decrypted_request["mode"] == "SignIn":
                            result = self.auth.authenticate_user(decrypted_request["username"], decrypted_request["password"])
                            response = f"Login status: {result}"
                        elif decrypted_request["mode"] == "SignUp":
                            result = self.auth.add_new_user(decrypted_request["username"], decrypted_request["password"])
                            response = "Registration successful" if result else "Registration failed"
                        else:
                            response = "Invalid request mode."

                        encrypted_response = self.session_encryptor.encrypt_text(response.encode(), self.session_key, self.session_iv)
                        client_socket.send(pickle.dumps(encrypted_response))
                    except Exception as e:
                        print(f"Error processing client request: {e}")
                        break
            except Exception as e:
                print(f"Error during client communication: {e}")
            finally:
                client_socket.close()

if __name__ == "__main__":
    server = Server()
    server.server_up()
