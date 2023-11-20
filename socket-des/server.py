from socket import *
import socket
import threading
import logging
import time
import sys
logging.basicConfig(level = logging.INFO)
SERVER_PORT = 8889

# Server socket code
class ProcessTheClient(threading.Thread):
    def __init__(self, connection, address, server):
        self.connection = connection
        self.address = address
        self.server = server
        threading.Thread.__init__(self)

    def run(self):
        try:
            while True:
                data = self.connection.recv(4096)
                if not data:
                    break
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