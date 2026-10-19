# ESP32 WireGuard Proxy

This is a vibecoded tool to place in a NAT-ted network and access devices in that from outside using your VPS.
Miniz is required along with the code here.

Use 16MB Flash Size, OPI PSRAM, Minimal spiffs

This Arduino IDE sketch connects an ESP32 to Wi-Fi, starts an outbound WireGuard peer to your VPS, and serves a plaintext HTTP proxy on both the Wi-Fi and WireGuard interfaces. It supports ordinary HTTP requests, plain WebSocket upgrades (a relict before CONNECT), and `CONNECT`. `CONNECT` opens an opaque TCP tunnel: the proxy does not terminate or inspect TLS, though TLS may pass through end-to-end.

The proxy and scan endpoints have no authentication. The proxy permits TCP connections to any port on the ESP32's directly connected Wi-Fi subnet, and the scan endpoint can ping hosts on that subnet. The firmware upload endpoint requires the configured OTA password, but HTTP is plaintext. Anyone who can reach these services on either interface can use them; do not expose them to untrusted clients or use the upload endpoint over an untrusted network.

## What you need

- An ESP32-S3 N16R8 board, such as the user's HW-678, and a USB data cable.
- A USB data cable, Wi-Fi credentials, and access to your existing VPS WireGuard configuration.
- The VPS endpoint and UDP port, its WireGuard public key, and a new key pair for the ESP32.

## Install Arduino IDE

1. Download Arduino IDE 2 from [arduino.cc/en/software](https://www.arduino.cc/en/software). On Linux, use the AppImage or the package for your distribution.
2. Start the IDE and open **File > Preferences**. Add this URL under **Additional boards manager URLs**:

   `https://espressif.github.io/arduino-esp32/package_esp32_index.json`

3. Open **Tools > Board > Boards Manager**, search for `esp32`, select version **2.0.17** of **esp32 by Espressif Systems**, and install it. WireGuard-ESP32 0.1.5 uses the older `tcpip_adapter.h` API and does not compile with ESP32 core 3.x.
4. Open **Tools > Manage Libraries**, search for `WireGuard-ESP32`, and install the library by Kenta Ida (version 0.1.5).
5. Connect the board. Choose **Tools > Board > esp32 > ESP32S3 Dev Module**. Under **Tools**, select **Flash Size > 16MB** and **PSRAM > OPI PSRAM** if available. Select the port for the USB connector you're using.

## Configure the WireGuard peers

The example uses tunnel addresses `10.77.0.1` for the VPS and `10.77.0.2` for the ESP32. Choose a different unused subnet if it overlaps your Wi-Fi LAN or another network.

On the VPS (or another trusted Linux machine with WireGuard tools installed), generate a separate key pair for the ESP32:

```sh
umask 077
wg genkey | tee esp32-private.key | wg pubkey > esp32-public.key
cat esp32-public.key
```

Put the contents of `esp32-private.key` in `WG_PRIVATE_KEY` in the ESP32's `config.h`. Add the contents of `esp32-public.key` to the VPS WireGuard interface:

```ini
[Peer]
PublicKey = ESP32_PUBLIC_KEY
AllowedIPs = 10.77.0.2/32
```

The VPS `AllowedIPs` entry identifies the ESP32 tunnel address. Remote WireGuard clients that should use the proxy must route `10.77.0.2/32` to the VPS peer. If clients and ESP32 connect to the VPS as separate WireGuard peers, the VPS must allow/forward traffic between those peers (IP forwarding and firewall rules, if applicable). You do **not** need to route the Wi-Fi LAN subnet through WireGuard: the ESP32 terminates the proxy connection and makes a separate connection to the LAN device itself.

Keep the VPS WireGuard UDP port reachable through its firewall. The ESP32 initiates the connection from behind NAT. WireGuard-ESP32 library version 0.1.5 uses a 10-second persistent keepalive by default. The sketch waits for NTP time before starting WireGuard and recreates the tunnel after Wi-Fi disconnects.

## Configure and upload

1. In Arduino IDE, open `arduino_wg_http_proxy/arduino_wg_http_proxy.ino`.
2. Copy `arduino_wg_http_proxy/config.example.h` to `arduino_wg_http_proxy/config.h` if `config.h` is not present. Edit `config.h` with your Wi-Fi credentials, ESP32 private key, VPS public key, endpoint, and tunnel address. Never share the private key or Wi-Fi password.
   Set `OTA_UPDATE_PASSWORD` in `config.h` to a long, unique password before using firmware uploads. The upload endpoint remains disabled if this setting is missing.
3. Make sure the ESP32 tunnel address matches the VPS peer `AllowedIPs` entry. This library's installed `begin()` API takes the tunnel IP, private key, endpoint, VPS public key, and port; it does not take a tunnel mask or gateway.
4. Choose **Sketch > Verify/Compile**, then **Sketch > Upload**.
5. Open **Tools > Serial Monitor**, set **115200 baud**, and watch for the Wi-Fi address and proxy-start message.

The private `config.h` is excluded by `.gitignore` to help avoid committing secrets.

## Connect to the proxy

Configure a client with an ordinary HTTP proxy at the ESP32 tunnel address and port:

```text
10.77.0.2:8080
```

For a client on the ESP32's Wi-Fi, use the Wi-Fi address printed in Serial Monitor instead. Both interfaces are accepted.

HTTP and `CONNECT` destinations must resolve to an IPv4 address on the ESP32's directly connected Wi-Fi subnet. For example, `CONNECT 192.168.1.50:443` can tunnel to a local HTTPS service if the ESP32 is on `192.168.1.0/24`. The proxy connection itself is plaintext HTTP; TLS inside the tunnel is opaque to the ESP32. Public addresses, other subnets, and IPv6 are rejected.

## Why an application proxy instead of routes and masquerading?

The ESP32 exposes one tunnel address and proxies application TCP traffic to its local Wi-Fi subnet; it does not advertise or route the whole LAN through WireGuard. This avoids subnet-route collisions when the VPS, remote client, or another network uses an overlapping private IP range. The Python VPS process can run as an ordinary user, and clients only need to configure an HTTP proxy to forward application traffic through the ESP32.

Dynamic ESP-side port forwards are possible too: a separate HTTP control endpoint could add and remove forwarding rules on request. That adds an API for managing network state, including its lifetime and access control, and is a deeper configuration surface than this deliberately narrow application-level forwarder. The proxy handles application TCP traffic without requiring LAN routes or masquerade/NAT rules. As a bonus, `python_vps.py` can compress the VPS-to-ESP32 tunnel bytes; a routed/NAT path would not provide that application-level compression.

Plain `ws://` requests can use an HTTP/1.1 WebSocket upgrade, which the ESP32 forwards and relays in the same per-client task. `wss://` remains supported through `CONNECT`. Idle WebSocket connections close after one hour. Tinyproxy's `ReversePath` handling strips WebSocket upgrade headers, so it cannot be used as the WebSocket-facing reverse proxy for this route. A WebSocket-aware reverse proxy such as Nginx can forward to the ESP's WireGuard address (not my usecase though, see the Python script):

```nginx
# Put the map directive inside nginx's http context.
map $http_upgrade $connection_upgrade {
   default upgrade;
   ''      close;
}

server {
   listen 80;

   location / {
      proxy_pass http://10.77.0.2:8080;
      proxy_http_version 1.1;
      proxy_set_header Host 192.168.8.151;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection $connection_upgrade;
      proxy_read_timeout 3600s;
      proxy_send_timeout 3600s;
   }
}
```

Replace the example WireGuard and LAN addresses with yours. Nginx must be able to route to the ESP's WireGuard IP, and its listener must be restricted to trusted clients because the ESP proxy has no authentication.

For the VPS-to-ESP leg, `python_vps.py` can compress the bytes inside its CONNECT tunnel. Keep `ENABLE_COMPRESSION = True` (the default) and run that script on the VPS; the ESP must be running this sketch version. The sketch uses the bundled miniz 2.2.0 software codec, not the ESP ROM codec; keep the `miniz*` source and header files beside the sketch. The script negotiates `zlib-block-v1` in CONNECT headers, then sends independent frames containing a signature, version, type, encoded length, decoded length, and at most 1024 decoded bytes. Each block uses zlib only when it becomes smaller; otherwise it is sent raw. The framing is between the Python process and ESP only: Nginx/WebSocket clients and the LAN service still exchange the original byte stream. Set `ENABLE_COMPRESSION = False` to use ordinary raw CONNECT instead.

This is transport compression, not WebSocket per-message compression, and it does not add encryption; WireGuard still protects the VPS-to-ESP hop. It can reduce traffic for plaintext `ws://` content, but `wss://` or other TLS-encrypted payloads are effectively incompressible and usually gain no savings. Compare transferred bytes and latency with representative traffic before relying on it.

The VPS uses zlib level 6, and the ESP uses miniz's default 128 search probes. These settings spend more CPU on compression than the fastest settings; check ESP latency under representative traffic.

Run the framing tests from the project root with:

```sh
python3 -m unittest discover -s . -p 'test_*.py'
```

## Discover LAN devices

Use the separate service directly, not through the proxy. To read current device info, including the Wi-Fi local IP and WireGuard tunnel IP, request `/info` from a WireGuard client:

```sh
curl http://10.77.0.2:8081/info
```

The JSON response includes `wifi_connected`, `local_ip`, `subnet_mask`, `gateway_ip`, `wireguard_started`, and `wireguard_ip`. From a client on the same Wi-Fi, replace `10.77.0.2` with the ESP32's Wi-Fi address.

To scan for LAN devices, request `/scan`:

```sh
curl http://10.77.0.2:8081/scan
```

The response is JSON containing the subnet, alive IPv4 addresses, and number of hosts scanned. The scan probes up to 16 hosts concurrently and supports subnets up to `/23`. It uses ICMP echo, so devices or firewalls that block ping will not appear even if their services are reachable. Port `8081` is unauthenticated, like the proxy.

## Update firmware over HTTP

Compile the sketch and upload its `.bin` firmware image to `/update` as a raw request body. The selected partition scheme must provide OTA app slots; `Update.begin()` will reject images when no suitable slot is available. For example, from a trusted machine on the Wi-Fi or WireGuard network:

```sh
curl --fail --data-binary @firmware.bin \
   -H 'X-OTA-Password: YOUR_OTA_UPDATE_PASSWORD' \
   http://10.77.0.2:8081/update
```

Replace `firmware.bin` with the compiled application image and use the ESP32's Wi-Fi address instead when uploading from that LAN. The board restarts after a successful update. The password is sent over plaintext HTTP, so use this only on a trusted network; WireGuard protects the VPS-to-ESP32 route when uploading through the tunnel.

## Troubleshooting

- **No serial port:** Try a USB data cable and another port. Some boards need a USB-UART driver or Linux serial-device permissions.
- **Upload fails:** Hold the board's **BOOT** button while upload begins, then release it when the IDE reports it is connecting.
- **Wi-Fi does not connect:** Check `WIFI_SSID` and `WIFI_PASSWORD`; watch Serial Monitor at 115200 baud.
- **WireGuard does not connect:** Check endpoint, UDP port, keys, and VPS `AllowedIPs`; confirm the firewall permits the WireGuard UDP port.
- **Proxy works on Wi-Fi but not over WireGuard:** Check that remote clients route the ESP32 tunnel IP to the VPS and that VPS forwarding/firewall rules allow client-to-peer traffic.
- **Proxy returns 403:** The target must be an IPv4 address on the same subnet as the ESP32's Wi-Fi address.
- **HTTPS fails:** Configure an ordinary HTTP proxy, not an HTTPS proxy. The client uses HTTP `CONNECT` to establish a raw tunnel for TLS.

The sketch handles up to four proxy clients concurrently, closes ordinary HTTP requests after each response, limits headers to 2048 bytes and request bodies to 2 MiB, and closes idle CONNECT tunnels after five minutes. The separate scan service runs concurrently with proxy handling. Chunked request bodies and `Expect: 100-continue` are not supported.


THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.