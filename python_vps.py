import socket
import struct
import threading
import zlib

# --- CONFIGURATION ---
LISTEN_HOST = "0.0.0.0"        # Local address for Nginx to talk to
LISTEN_PORT = 8889               # Port your VPS/Nginx will listen on
ESP32_PROXY_IP = "192.168.6.15"      # ESP32's WireGuard IP
ESP32_PROXY_PORT = 8080          # Port of the HTTP proxy running on the ESP32
TARGET_LAN_HOST = "192.168.0.1"  # The actual target device inside the foreign LAN
TARGET_LAN_PORT = 80             # The target device's port (e.g., 80, 443, 8080)
ENABLE_COMPRESSION = True
# ---------------------

COMPRESSION_HEADER = "X-ESP32-Proxy-Compression"
COMPRESSION_MODE = "zlib-block-v1"
FRAME_MAGIC = b"EC"
FRAME_VERSION = 1
FRAME_RAW = 0
FRAME_ZLIB = 1
FRAME_HEADER = struct.Struct("!2sBBHH")
BLOCK_SIZE = 1024
MAX_ENCODED_SIZE = 1024
MAX_RESPONSE_HEADER = 8192


class ProtocolError(ValueError):
    pass


def encode_frame(data):
    if not data or len(data) > BLOCK_SIZE:
        raise ProtocolError("invalid uncompressed block length")

    compressed = zlib.compress(data, level=1)
    if len(compressed) < len(data):
        frame_type = FRAME_ZLIB
        payload = compressed
    else:
        frame_type = FRAME_RAW
        payload = data

    if len(payload) > MAX_ENCODED_SIZE:
        raise ProtocolError("encoded block exceeds frame limit")
    header = FRAME_HEADER.pack(
        FRAME_MAGIC, FRAME_VERSION, frame_type, len(payload), len(data)
    )
    return header + payload


def decode_frame(header, payload):
    if len(header) != FRAME_HEADER.size:
        raise ProtocolError("invalid frame header length")
    magic, version, frame_type, encoded_length, decoded_length = FRAME_HEADER.unpack(header)
    if magic != FRAME_MAGIC or version != FRAME_VERSION:
        raise ProtocolError("invalid frame signature or version")
    if not 0 < encoded_length <= MAX_ENCODED_SIZE:
        raise ProtocolError("invalid encoded block length")
    if not 0 < decoded_length <= BLOCK_SIZE or len(payload) != encoded_length:
        raise ProtocolError("invalid decoded block length")

    if frame_type == FRAME_RAW:
        if encoded_length != decoded_length:
            raise ProtocolError("raw frame lengths do not match")
        return payload
    if frame_type != FRAME_ZLIB:
        raise ProtocolError("unknown frame type")

    try:
        decoder = zlib.decompressobj()
        decoded = decoder.decompress(payload, decoded_length + 1)
    except zlib.error as error:
        raise ProtocolError("invalid compressed block") from error
    if (len(decoded) != decoded_length or not decoder.eof or
            decoder.unused_data or decoder.unconsumed_tail):
        raise ProtocolError("compressed block length mismatch")
    return decoded


class SocketBuffer:
    def __init__(self, initial=b""):
        self.data = bytearray(initial)

    def read_exact(self, source, length):
        while len(self.data) < length:
            chunk = source.recv(length - len(self.data))
            if not chunk:
                raise EOFError("peer closed during frame")
            self.data.extend(chunk)
        result = bytes(self.data[:length])
        del self.data[:length]
        return result


def read_frame(source, buffered):
    header = buffered.read_exact(source, FRAME_HEADER.size)
    _, _, _, encoded_length, _ = FRAME_HEADER.unpack(header)
    if not 0 < encoded_length <= MAX_ENCODED_SIZE:
        raise ProtocolError("invalid encoded block length")
    payload = buffered.read_exact(source, encoded_length)
    return decode_frame(header, payload)


def forward(source, destination):
    try:
        while True:
            data = source.recv(4096)
            if not data:
                break
            destination.sendall(data)
    except Exception:
        pass
    finally:
        source.close()
        destination.close()


def close_tunnel(client_sock, proxy_sock):
    for sock in (client_sock, proxy_sock):
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()


def forward_compressed_to_proxy(client_sock, proxy_sock):
    try:
        while True:
            data = client_sock.recv(BLOCK_SIZE)
            if not data:
                break
            proxy_sock.sendall(encode_frame(data))
    except (OSError, ProtocolError):
        pass
    finally:
        close_tunnel(client_sock, proxy_sock)


def forward_compressed_to_client(proxy_sock, client_sock, initial_data=b""):
    buffered = SocketBuffer(initial_data)
    try:
        while True:
            client_sock.sendall(read_frame(proxy_sock, buffered))
    except (EOFError, OSError, ProtocolError):
        pass
    finally:
        close_tunnel(client_sock, proxy_sock)


def read_proxy_response(proxy_sock):
    response = bytearray()
    delimiter = b"\r\n\r\n"
    while delimiter not in response:
        if len(response) >= MAX_RESPONSE_HEADER:
            raise ProtocolError("ESP proxy response headers are too large")
        chunk = proxy_sock.recv(min(1024, MAX_RESPONSE_HEADER - len(response)))
        if not chunk:
            raise EOFError("ESP proxy closed before responding")
        response.extend(chunk)

    header_end = response.index(delimiter)
    header_bytes = bytes(response[:header_end])
    trailing_bytes = bytes(response[header_end + len(delimiter):])
    lines = header_bytes.decode("iso-8859-1").split("\r\n")
    status_parts = lines[0].split(" ", 2)
    if len(status_parts) < 2 or not status_parts[1].isdigit():
        raise ProtocolError("malformed ESP proxy status line")
    headers = {}
    for line in lines[1:]:
        if ":" not in line:
            raise ProtocolError("malformed ESP proxy response header")
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return int(status_parts[1]), headers, trailing_bytes, header_bytes


def handle_client(client_sock):
    proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # 1. Connect to the ESP32 HTTP Proxy over WireGuard
        proxy_sock.connect((ESP32_PROXY_IP, ESP32_PROXY_PORT))

        # 2. Issue the HTTP CONNECT command to target the internal LAN device
        connect_req = (
            f"CONNECT {TARGET_LAN_HOST}:{TARGET_LAN_PORT} HTTP/1.1\r\n"
            f"Host: {TARGET_LAN_HOST}:{TARGET_LAN_PORT}\r\n"
        )
        if ENABLE_COMPRESSION:
            connect_req += f"{COMPRESSION_HEADER}: {COMPRESSION_MODE}\r\n"
        connect_req += "\r\n"
        proxy_sock.sendall(connect_req.encode("ascii"))

        # 3. Validate the proxy response before switching to framed data.
        proxy_sock.settimeout(15)
        status, response_headers, trailing_bytes, header_bytes = read_proxy_response(proxy_sock)
        if status != 200:
            print(f"[-] Proxy refused tunnel: {header_bytes.decode(errors='ignore')}")
            client_sock.close()
            proxy_sock.close()
            return
        if (ENABLE_COMPRESSION and
                response_headers.get(COMPRESSION_HEADER.lower()) != COMPRESSION_MODE):
            raise ProtocolError("ESP proxy did not acknowledge compression mode")
        proxy_sock.settimeout(None)

        if ENABLE_COMPRESSION:
            t1 = threading.Thread(
                target=forward_compressed_to_proxy,
                args=(client_sock, proxy_sock),
                daemon=True,
            )
            t2 = threading.Thread(
                target=forward_compressed_to_client,
                args=(proxy_sock, client_sock, trailing_bytes),
                daemon=True,
            )
        else:
            if trailing_bytes:
                client_sock.sendall(trailing_bytes)
            t1 = threading.Thread(target=forward, args=(client_sock, proxy_sock), daemon=True)
            t2 = threading.Thread(target=forward, args=(proxy_sock, client_sock), daemon=True)
        t1.start()
        t2.start()

    except Exception as e:
        print(f"[-] Tunnel error: {e}")
        client_sock.close()
        proxy_sock.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_HOST, LISTEN_PORT))
    server.listen(5)
    print(f"[*] Local tunnel forwarder listening on {LISTEN_HOST}:{LISTEN_PORT} -> tunneling via ESP32 to {TARGET_LAN_HOST}:{TARGET_LAN_PORT}")

    while True:
        client_sock, addr = server.accept()
        threading.Thread(target=handle_client, args=(client_sock,), daemon=True).start()

if __name__ == "__main__":
    main()
