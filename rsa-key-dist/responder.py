from socket import *
import socket
import threading
import logging
import time
import sys
import uuid
import math
logging.basicConfig(level = logging.INFO)
SERVER_PORT = 8889
DES_KEY = "8b52aec7d4b5229f"
responder_p = 31441855762377376387238055386392902749182882698080792109997248657702523690265653201687528385374736644889860884654510791901187926391617558072753036919671889631780060837969517903495224753139515969054687
responder_q = 21952308615481684104997154481061803308440924546357714105509059303507549130843065341902473528177446465377549287229826870324973627605373173341391600597791424739096448593483285265618752237518511791641563
responder_e = 65537
responder_n = responder_p * responder_q

# RSA code
def generate_rsa(p = 1047291232323135235223, q = 44431031398614647, e = 65537):
  n = p * q
  print(f'n: {n}')
  phi = (p - 1) * (q - 1)
  print(f'phi: {phi}')
  assert math.gcd(e, phi) == 1 and e < phi
  d = pow(e, -1, phi)
  print(f'd: {d}')
  return d

def encrypt_rsa(m = 13235323532532432432432, e = 65537, n = 46532229626843048532066946634678111281):
  c = pow(m, e, n)
  print(f'c: {c}')
  return c

def decrypt_rsa(c = 13235323532532432432432, d = 19115724220569988974646693314483787021, n = 46532229626843048532066946634678111281):
  m = pow(c, d, n)
  print(f'm: {m}')
  return m

# Server socket code
class ProcessTheClient(threading.Thread):
    def __init__(self, connection, address, server):
        self.connection = connection
        self.address = address
        self.server = server
        threading.Thread.__init__(self)

    def run(self):
        try:
            # Generate RSA & share public key (PUa)
            responder_d = generate_rsa(responder_p, responder_q, responder_e)

            # Key Distribution
            # Receive initiator public key (PUa)
            recv_data = self.connection.recv(4096)
            PUa = eval(recv_data.decode())
            logging.info(f"[SERVER] received initiator public key: PUa-e:{PUa['e']}, PUa-n:{PUa['n']}")
            # Share responder public key (PUb) to initiator
            PUb = {
                'e': responder_e,
                'n': responder_n
            }
            logging.info(f"[SERVER] sharing public key PUb-e:{PUb['e']}, PUb-n:{PUb['n']} to initiator..")
            self.connection.sendall(str(PUb).encode())

            # Step 1 - receive msg 1 from initiator
            recv_data = self.connection.recv(4096)
            msg1 = decrypt_rsa(int(recv_data.decode()), responder_d, responder_n)
            msg1_bytes = msg1.to_bytes((msg1.bit_length() + 7) // 8)
            msg1 = eval(msg1_bytes.decode('utf-8'))

            logging.info(f'[SERVER] receives msg1: {str(msg1)}')

            # Step 2
            N2 = str(uuid.uuid4())
            logging.info(f"[SERVER] N2: {N2}")
            msg2 = {
                'message1': msg1['message1'],
                'message2': N2
            }
            logging.info(f"[SERVER] sending msg2: {str(msg2)}")
            self.connection.sendall(repr(encrypt_rsa(int.from_bytes(((str(msg2)).encode('utf-8'))), PUa['e'], PUa['n'])).encode())

            # Step 3 - receive msg 3 from initiator
            recv_data = self.connection.recv(4096)
            msg3 = decrypt_rsa(int(recv_data.decode()), responder_d, responder_n)
            msg3_bytes = msg3.to_bytes((msg3.bit_length() + 7) // 8)
            msg3 = eval(msg3_bytes.decode('utf-8'))
            logging.info(f'[SERVER] receives msg3: {str(msg3)}')

            assert N2 == msg3['message3']

            # Step 4
            msg4 = {
                'message1': msg1['message1'],
                'symmetric_key': DES_KEY
            }
            logging.info(f"[SERVER] sending msg4: {str(msg4)}")
            self.connection.sendall(repr(encrypt_rsa(int.from_bytes(((str(msg4)).encode('utf-8'))), PUa['e'], PUa['n'])).encode())

            assert msg1 and msg2 and msg3 and msg4

            logging.info(f"[SERVER] key distribution complete!")

            while True:
                data = self.connection.recv(4096)
                if not data:
                    break
                logging.info(f"{data.decode()}")
                self.server.broadcast(data, sender=self)
        except Exception as e:
            logging.warning(f"error reading from {self.address}: {str(e)}")
        finally:
            logging.info(f"connection from {self.address} closed")
            self.connection.close()
            self.server.remove_client(self)

class Server(threading.Thread):
    def __init__(self):
        self.the_clients = []
        self.my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        threading.Thread.__init__(self)

    def run(self):
        self.my_socket.bind(('0.0.0.0', SERVER_PORT))
        self.my_socket.listen(1)
        while True:
            self.connection, self.client_address = self.my_socket.accept()
            logging.info(f"connection from {self.client_address}")
            clt = ProcessTheClient(self.connection, self.client_address, self)
            clt.start()
            self.the_clients.append(clt)

    def broadcast(self, message, sender):
        send_data = {
            'sender_ip': sender.address[0],
            'sender_port': sender.address[1],
            'message': message.decode('utf-8')
        }
        logging.info(f"{send_data['sender_ip']}:{send_data['sender_port']} sends {send_data['message']}")
        for client in self.the_clients:
            
            if client != sender:
                try:
                    client.connection.sendall(str(send_data).encode())
                except:
                    logging.warning(f"{client.address} unavailable, removing from list")
                    self.remove_client(client)

    def remove_client(self, client):
        if client in self.the_clients:
            self.the_clients.remove(client)

def main():
    svr = Server()
    svr.start()

if __name__ == "__main__":
    main()