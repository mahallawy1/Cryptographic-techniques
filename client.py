import socket
import pickle
from crypto.AsymmetricCipher import RSA
from crypto.SymmetricCipher import AESEncryption, Encryptor
from KeyManagement import KeyManager

class Client:
    def __init__(self):
        self.socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_host = socket.gethostname()
        self.server_port = 12345
        aes_strategy = AESEncryption()
        self.session_iv = aes_strategy.generate_iv()
        self.session_key = aes_strategy.generate_key(32)
        self.encryptor = Encryptor(aes_strategy)

    def start_client(self):
        try:
            self.socket_client.connect((self.server_host, self.server_port))
            print("Connected to the server.")

            # Step 1: Receive public key from the server
            server_response = self.socket_client.recv(4096)
            if not server_response:
                print("Error: No response from server.")
                return
            server_public_key = KeyManager().pem_to_rsa_public_key(pickle.loads(server_response)["public_key"])
            print("Server's public key received successfully.")

            # Step 2: Send session key and IV
            rsa = RSA()
            session_data = {
                "mode": rsa.encrypt("AES256".encode(), server_public_key),
                "key": rsa.encrypt(self.session_key, server_public_key),
                "iv": rsa.encrypt(self.session_iv, server_public_key),
            }
            self.socket_client.send(pickle.dumps(session_data))
            print("Session key and IV sent to the server.")
            print(f"Session Key: {self.session_key}")
            print(f"IV: {self.session_iv}")

            # Step 3: Handle user input for login or registration
            while True:
                user_choice = input("Select an option:\n0 - Login\n1 - Register\nChoice: ")
                if user_choice not in ["0", "1"]:
                    print("Invalid choice. Exiting.")
                    break

                username = input("Enter Username: ")
                password = input("Enter Password: ")

                mode = "SignIn" if user_choice == "0" else "SignUp"
                encrypted_request = {
                    "mode": self.encryptor.encrypt_text(mode.encode(), self.session_key, self.session_iv),
                    "username": self.encryptor.encrypt_text(username.encode(), self.session_key, self.session_iv),
                    "password": self.encryptor.encrypt_text(password.encode(), self.session_key, self.session_iv),
                }
                self.socket_client.send(pickle.dumps(encrypted_request))

                # Receive response
                try:
                    server_response = pickle.loads(self.socket_client.recv(4096))
                    decrypted_response = self.encryptor.decrypt_text(server_response, self.session_key, self.session_iv).decode()
                    print("Server Response:", decrypted_response)
                except Exception as e:
                    print(f"Error receiving or processing server response: {e}")
                    break
        except Exception as e:
            print(f"Error connecting to server: {e}")
        finally:
            self.socket_client.close()

if __name__ == "__main__":
    client_instance = Client()
    client_instance.start_client()
