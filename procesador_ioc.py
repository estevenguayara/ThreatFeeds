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

def extraer_datos(body):
    """Extrae los campos del formulario usando Regex."""
    tipo = re.search(r'### Tipo de IoC\s+(.*?)\s+', body)
    valor = re.search(r'### Valor del Indicador.*?\s+(.*?)\s+', body)
    fuente = re.search(r'### Fuente del Indicador\s+(.*?)\s+', body)
    
    return {
        "tipo": tipo.group(1).strip() if tipo else None,
        "valor": valor.group(1).strip() if valor else None,
        "fuente": fuente.group(1).strip() if fuente else None
    }

def validar_formato(tipo, valor):
    """Valida si el valor ingresado es una IP o URL real."""
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
    """Consulta la reputación en VirusTotal."""
    header = {"x-apikey": VT_APIKEY}
    endpoint = "ip_addresses" if tipo == "IP" else "urls"
    # Para URLs, VT requiere que el valor esté en base64 o usar el ID de análisis, 
    # simplificaremos a IP para este ejemplo base.
    url = f"https://www.virustotal.com/api/v3/{endpoint}/{valor}"
    
    try:
        response = requests.get(url, headers=header)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return stats.get('malicious', 0)
    except:
        return 0
    return 0

def enviar_comentario_github(mensaje, cerrar=False):
    """Escribe feedback en el Issue de GitHub."""
    url = f"https://api.github.com/repos/{REPO}/issues/{ISSUE_NUMBER}/comments"
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    requests.post(url, json={"body": mensaje}, headers=headers)
    
    if cerrar:
        url_issue = f"https://api.github.com/repos/{REPO}/issues/{ISSUE_NUMBER}"
        requests.patch(url_issue, json={"state": "closed"}, headers=headers)

# --- EJECUCIÓN PRINCIPAL ---
datos = extraer_datos(ISSUE_BODY)

if not validar_formato(datos['tipo'], datos['valor']):
    enviar_comentario_github(f"❌ Error: El formato de {datos['tipo']} es incorrecto.", cerrar=True)
    exit(0)

reputacion = consultar_virustotal(datos['tipo'], datos['valor'])

if reputacion >= 1: # Si al menos 1 motor lo marca como malicioso
    # Lógica de enrutamiento de archivos
    sufijo = "1" if "CL" in datos['fuente'] else "2" if "CO" in datos['fuente'] else "interno"
    nombre_archivo = f"IoC_{datos['tipo']}{sufijo}.txt"
    
    with open(nombre_archivo, "a") as f:
        f.write(f"{datos['valor']} # Fuente: {datos['fuente']} | VT: {reputacion}\n")
    
    enviar_comentario_github(f"✅ IoC validado ({reputacion} detecciones). Añadido a `{nombre_archivo}`.", cerrar=True)
else:
    enviar_comentario_github(f"⚠️ VirusTotal reporta 0 detecciones. No se añadirá al bloqueo automático.", cerrar=True)
