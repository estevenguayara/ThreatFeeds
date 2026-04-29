import os
import re
import requests
import ipaddress

# --- CONFIGURACIÓN DE VARIABLES ---
VT_APIKEY = os.getenv('VT_APIKEY')
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
ISSUE_BODY = os.getenv('ISSUE_BODY', '')
ISSUE_NUMBER = os.getenv('ISSUE_NUMBER')
REPO = os.getenv('REPO')
# Esta variable la entrega GitHub automáticamente: es el usuario que activó la Action
USUARIO_ACTUAL = os.getenv('GITHUB_ACTOR') 

# --- 🛡️ LISTA BLANCA DE USUARIOS AUTORIZADOS ---
# Agrega aquí los nombres de usuario de GitHub de las personas permitidas
USUARIOS_AUTORIZADOS = ["estevenguayara", "usuario_analista_1", "usuario_analista_2"]

def enviar_comentario_github(mensaje, cerrar=False):
    """Publica un comentario en el Issue y opcionalmente lo cierra."""
    url = f"https://api.github.com/repos/{REPO}/issues/{ISSUE_NUMBER}/comments"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    requests.post(url, json={"body": mensaje}, headers=headers)
    if cerrar:
        requests.patch(f"https://api.github.com/repos/{REPO}/issues/{ISSUE_NUMBER}", 
                       json={"state": "closed"}, headers=headers)

# --- VALIDACIÓN DE SEGURIDAD (OPCIÓN 1) ---
if USUARIO_ACTUAL not in USUARIOS_AUTORIZADOS:
    enviar_comentario_github(
        f"🚫 **Acceso Denegado**: El usuario @{USUARIO_ACTUAL} no está en la lista blanca para procesar bloqueos automáticos.", 
        cerrar=True
    )
    print(f"ERROR: Intento de ejecución no autorizado por {USUARIO_ACTUAL}")
    exit(0)

# --- FUNCIONES DE EXTRACCIÓN Y PROCESAMIENTO ---
def extraer_datos(body):
    """Analiza el cuerpo del Issue para extraer el valor y la fuente."""
    clean_body = body.replace('\r', '')

    # 1. Extraer Valor (IP o URL)
    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', clean_body)
    url_match = re.search(r'(https?://[^\s\n\r]+)', clean_body)

    valor = None
    tipo = "Desconocido"

    if ip_match:
        valor = ip_match.group(1).strip()
        tipo = "IP"
    elif url_match:
        valor = url_match.group(1).strip()
        tipo = "URL"

    # 2. Identificar Fuente (Mapeo de las 5 fuentes solicitadas)
    # Buscamos palabras clave en el texto del Issue
    fuente_final = "Interno" # Valor por defecto
    
    fuentes_disponibles = {
        "CSIRT-CL": "CSIRT-CL",
        "CSIRT-CO": "CSIRT-CO",
        "TISAL": "Tisal",
        "SOLGAS": "Solgas",
        "INTERNO": "Interno"
    }

    body_upper = clean_body.upper()
    for clave, nombre_formateado in fuentes_disponibles.items():
        if clave in body_upper:
            fuente_final = nombre_formateado
            break

    return {"tipo": tipo, "valor": valor, "fuente": fuente_final}

def validar_formato(tipo, valor):
    """Verifica que el valor extraído sea técnicamente correcto."""
    if not valor: return False
    if tipo == "IP":
        try:
            ipaddress.ip_address(valor)
            return True
        except:
            return False
    return valor.startswith(("http://", "https://"))

def consultar_virustotal(tipo, valor):
    """Consulta la reputación en VirusTotal si hay API Key."""
    if not VT_APIKEY:
        print("Aviso: Sin VT_APIKEY, se procesará con reputación mínima.")
        return 1 # Si no hay clave, dejamos pasar para no bloquear el flujo
        
    if tipo == "IP":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{valor}"
        headers = {"x-apikey": VT_APIKEY}
        try:
            res = requests.get(url, headers=headers, timeout=10)
            if res.status_code == 200:
                return res.json()['data']['attributes']['last_analysis_stats'].get('malicious', 0)
        except Exception as e:
            print(f"Error consultando VT: {e}")
    return 1 # Por defecto permitimos el proceso si falla la consulta

def enviar_comentario_github(mensaje, cerrar=False):
    """Publica un comentario en el Issue y opcionalmente lo cierra."""
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

# Validar que encontramos algo útil
if not datos['valor'] or not validar_formato(datos['tipo'], datos['valor']):
    enviar_comentario_github(
        f"❌ **Error de Extracción**\nNo se detectó una IP o URL válida en el formulario.", 
        cerrar=True
    )
    exit(0)

# Consultar reputación
detecciones = consultar_virustotal(datos['tipo'], datos['valor'])

# Umbral: Si tiene 1 o más detecciones, va a la lista de bloqueo
if detecciones >= 1:
    # Construcción del nombre del archivo: IoC_IP_Tisal.txt, etc.
    nombre_archivo = f"IoC_{datos['tipo']}_{datos['fuente']}.txt"
    
    # Escribir en el archivo (Modo Append 'a')
    with open(nombre_archivo, "a") as f:
        f.write(f"{datos['valor']}\n")
    
    enviar_comentario_github(
        f"✅ **Bloqueo Automatizado**\n"
        f"- **Indicador:** `{datos['valor']}`\n"
        f"- **Fuente detectada:** {datos['fuente']}\n"
        f"- **Detecciones VT:** {detecciones}\n"
        f"- **Archivo actualizado:** `{nombre_archivo}`", 
        cerrar=True
    )
else:
    enviar_comentario_github(
        f"⚠️ **Análisis Finalizado**\nEl indicador `{datos['valor']}` tiene 0 detecciones en VirusTotal. No se añadirá a las listas de bloqueo.", 
        cerrar=True
    )
