import socket
import pickle
import threading


class Communication:
    def __init__(self, is_server=False, host='localhost', port=5000):
        self._mode = 'server' if is_server else 'client'
        self._host = host
        self._port = port
        self._mutex = threading.Lock()

        if self._mode == 'server':
            self._server_setup()
        else:
            self._client_setup()

    def _server_setup(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind((self._host, self._port))
        self._sock.listen(1)
        print("[Comm] Awaiting incoming connection...")
        self._conn, _ = self._sock.accept()
        print("[Comm] Connection established with client")

    def _client_setup(self):
        self._conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._conn.connect((self._host, self._port))
        print("[Comm] Connected to server")
    def transmit(self, msg_type, *payload):
        """Package and send a message tuple."""
        packet = pickle.dumps((msg_type, *payload))
        header = len(packet).to_bytes(4, 'big')
        with self._mutex:
            self._conn.sendall(header + packet)

    def listen(self, expect_type=None):
        """Receive and decode a message, optionally match a type."""
        header = self._recv_bytes(4)
        size = int.from_bytes(header, 'big')
        body = self._recv_bytes(size)
        msg = pickle.loads(body)

        if expect_type and msg[0] != expect_type:
            return None
        return msg

    def _recv_bytes(self, n):
        """Ensure exactly n bytes are read from the socket."""
        chunks = []
        remaining = n
        while remaining > 0:
            chunk = self._conn.recv(remaining)
            if not chunk:
                raise ConnectionError("Disconnected unexpectedly")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b''.join(chunks)

    def disconnect(self):
        self._conn.close()
        if self._mode == 'server':
            self._sock.close()
