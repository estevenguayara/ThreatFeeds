import re
import requests
import ipaddress

# --- CONFIGURACIÓN DE VARIABLES ---
VT_APIKEY = os.getenv('VT_APIKEY')
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
ISSUE_BODY = os.getenv('ISSUE_BODY', '')
ISSUE_NUMBER = os.getenv('ISSUE_NUMBER')
REPO = os.getenv('REPO')

def extraer_datos(body):
    """Extrae datos usando búsqueda de patrones, ignorando el ruido de Markdown."""
    # 1. Limpiar el cuerpo de posibles saltos de línea de Windows (\r)
    clean_body = body.replace('\r', '')

    # 2. Extraer Valor (Busca algo que parezca IP o una URL simple)
    # Buscamos primero un patrón de IP (4 grupos de números)
    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', clean_body)
    # Si no hay IP, buscamos algo que empiece con http
    url_match = re.search(r'(https?://[^\s\n\r]+)', clean_body)

    valor = None
    tipo = "Desconocido"

    if ip_match:
        valor = ip_match.group(1).strip()
        tipo = "IP"
    elif url_match:
        valor = url_match.group(1).strip()
        tipo = "URL"

    # 3. Extraer Fuente (Buscamos palabras clave CL o CO)
    fuente = "Interno"
    if "CL" in clean_body.upper():
        fuente = "CSIRT-CL"
    elif "CO" in clean_body.upper():
        fuente = "CSIRT-CO"

    datos = {"tipo": tipo, "valor": valor, "fuente": fuente}
    print(f"DEBUG: Datos procesados -> {datos}")
    return datos

def validar_formato(tipo, valor):
    """Valida estrictamente el valor final."""
    if not valor:
        return False
    if tipo == "IP":
        try:
            ipaddress.ip_address(valor)
            return True
        except ValueError:
            return False
    elif tipo == "URL":
        return valor.startswith(("http://", "https://"))
    return False

def consultar_virustotal(tipo, valor):
    """Consulta reputación en VirusTotal."""
    if not VT_APIKEY or VT_APIKEY == "":
        print("Aviso: No hay VT_APIKEY, saltando consulta.")
        return 0
        
    header = {"x-apikey": VT_APIKEY}
    # VirusTotal no acepta URLs planas fácilmente, solo IPs para este ejemplo
    if tipo == "IP":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{valor}"
        try:
            response = requests.get(url, headers=header, timeout=10)
            if response.status_code == 200:
                stats = response.json()['data']['attributes']['last_analysis_stats']
                return stats.get('malicious', 0)
        except Exception as e:
            print(f"Error VT: {e}")
    return 0

def enviar_comentario_github(mensaje, cerrar=False):
    """Envía feedback al Issue."""
    url = f"https://api.github.com/repos/{REPO}/issues/{ISSUE_NUMBER}/comments"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    requests.post(url, json={"body": mensaje}, headers=headers)
    
    if cerrar:
        requests.patch(f"https://api.github.com/repos/{REPO}/issues/{ISSUE_NUMBER}", 
                       json={"state": "closed"}, headers=headers)

# --- EJECUCIÓN PRINCIPAL ---
datos = extraer_datos(ISSUE_BODY)

# Validamos si encontramos algo
if not datos['valor'] or not validar_formato(datos['tipo'], datos['valor']):
    enviar_comentario_github(
        f"❌ **Error de Formato**\nNo pude extraer una IP o URL válida. \nValor detectado: `{datos['valor']}`", 
        cerrar=True
    )
    exit(0)

# Consultamos reputación
reputacion = consultar_virustotal(datos['tipo'], datos['valor'])

# Si tiene al menos 1 detección o si es una IP válida (puedes ajustar el umbral)
if reputacion >= 1:
    sufijo = "1" if "CL" in datos['fuente'] else "2" if "CO" in datos['fuente'] else "interno"
    nombre_archivo = f"IoC_{datos['tipo']}{sufijo}.txt"
    
    # Escribir en el archivo (solo la IP/URL para que el Firewall no se confunda)
    with open(nombre_archivo, "a") as f:
        f.write(f"{datos['valor']}\n")
    
    enviar_comentario_github(
        f"✅ **IoC Procesado**\n- **Valor:** `{datos['valor']}`\n- **Detecciones VT:** {reputacion}\n- **Destino:** `{nombre_archivo}`", 
        cerrar=True
    )
else:
    enviar_comentario_github(
        f"⚠️ **Resultado Limpio en VirusTotal**\nEl indicador `{datos['valor']}` tiene 0 detecciones. No se añadirá a la lista de bloqueo automática.", 
        cerrar=True
    )
