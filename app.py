import streamlit as st
import mailparser
import extract_msg
import re
import requests
import base64

# Configuración de la ventana del navegador
st.set_page_config(
    page_title="Phishing Investigation Lab",
    page_icon="🛡️",
    layout="wide"
)


def parse_email_input(uploaded_file, raw_headers):
    if uploaded_file is not None:
        file_name = uploaded_file.name.lower()

        if file_name.endswith('.msg'):
            msg = extract_msg.Message(uploaded_file)
            return {
                "type": "msg",
                "subject": msg.subject or "Sin Asunto",
                "from": msg.sender or "Desconocido",
                "return_path": "N/A (formato MSG)",
                "headers": msg.header.as_string() if msg.header else "",
                "body": msg.body or ""
            }
        else:
            raw_content = uploaded_file.getvalue().decode("utf-8", errors="ignore")
            parser = mailparser.parse_from_string(raw_content)

            from_addr = parser.from_
            if isinstance(from_addr, list) and len(from_addr) > 0:
                name, email = from_addr[0]
                from_addr = f"{name} <{email}>" if name else email

            return_path = parser.headers.get("Return-Path", "N/A")

            return {
                "type": "eml",
                "subject": parser.subject or "Sin Asunto",
                "from": from_addr,
                "return_path": return_path,
                "headers": raw_content,
                "body": parser.body or ""
            }

    elif raw_headers.strip():
        parser = mailparser.parse_from_string(raw_headers)
        from_addr = parser.from_
        if isinstance(from_addr, list) and len(from_addr) > 0:
            name, email = from_addr[0]
            from_addr = f"{name} <{email}>" if name else email

        return {
            "type": "raw",
            "subject": parser.subject or "Sin Asunto",
            "from": from_addr,
            "return_path": parser.headers.get("Return-Path", "N/A"),
            "headers": raw_headers,
            "body": raw_headers
        }

    return None


def extract_urls(text):
    """ Extrae URLs y las desarma (defang) eliminando duplicados """
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    urls = list(set(re.findall(url_pattern, text)))
    defanged_urls = [url.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]") for url in
                     urls]
    return urls, defanged_urls


def extract_ip_addresses(headers_text):
    """ Extrae direcciones IP públicas de las cabeceras 'Received' """
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    all_ips = re.findall(ip_pattern, headers_text)

    public_ips = []
    for ip in all_ips:
        if not (ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("0.")):
            if ip not in public_ips:
                public_ips.append(ip)
    return public_ips


def analyze_auth_headers(headers_text):
    """ Analiza el estado de SPF, DKIM y DMARC en los encabezados """
    headers_lower = headers_text.lower()

    spf_status = "UNKNOWN"
    if "spf=pass" in headers_lower:
        spf_status = "PASS"
    elif "spf=softfail" in headers_lower or "spf=fail" in headers_lower:
        spf_status = "FAIL"

    dkim_status = "UNKNOWN"
    if "dkim=pass" in headers_lower:
        dkim_status = "PASS"
    elif "dkim=none" in headers_lower or "dkim=fail" in headers_lower:
        dkim_status = "FAIL"

    dmarc_status = "UNKNOWN"
    if "dmarc=pass" in headers_lower:
        dmarc_status = "PASS"
    elif "dmarc=fail" in headers_lower:
        dmarc_status = "FAIL"

    return spf_status, dkim_status, dmarc_status


def check_vt_url(api_key, target_url):
    """ Consulta VirusTotal v3 API para una URL dada """
    try:
        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        headers = {"x-apikey": api_key}
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            return stats
        elif response.status_code == 404:
            return "NOT_FOUND"
        else:
            return "ERROR"
    except Exception as e:
        return f"ERROR: {str(e)}"


# --- INTERFAZ GRÁFICA ---

st.title("🛡️ Phishing Investigation & Header Analyzer")
st.markdown("### Analizador de Correos Sospechosos e Investigación de Incidentes")
st.markdown("---")

# --- BARRA LATERAL CON SESSION STATE ---
with st.sidebar:
    st.header("⚙️ Configuración & API Keys")

    # Inicializar variable de estado para la API Key
    if "vt_api_key" not in st.session_state:
        st.session_state["vt_api_key"] = ""

    # Si no hay key guardada, mostrar el input
    if not st.session_state["vt_api_key"]:
        input_key = st.text_input(
            "VirusTotal API Key",
            type="password",
            help="Ingresa tu API Key. Se guardará de forma segura en la sesión actual."
        )
        if input_key:
            st.session_state["vt_api_key"] = input_key
            st.success("🔒 ¡API Key configurada en memoria!")
            st.rerun()
    else:
        # Si ya existe, ocultar el input y mostrar estado seguro
        st.success("🟢 API Key Cargada (En memoria)")
        if st.button("🗑️ Borrar / Cambiar API Key"):
            st.session_state["vt_api_key"] = ""
            st.rerun()

    vt_api_key = st.session_state["vt_api_key"]

col_upload, col_preview = st.columns([1, 1])

with col_upload:
    st.subheader("📥 Cargar Evidencia")
    uploaded_file = st.file_uploader("Sube un archivo de correo (.eml, .msg o .txt)", type=["eml", "msg", "txt"])
    raw_headers = st.text_area("O pega los encabezados en texto plano:", height=200)

email_data = parse_email_input(uploaded_file, raw_headers)

with col_preview:
    st.subheader("🔍 Resumen Visual del Incidente")
    if not email_data:
        st.info("Esperando que subas un correo (.eml, .msg) o pegues los encabezados a la izquierda...")
    else:
        st.success("¡Evidencia procesada correctamente!")

        # Metadatos Limpios
        st.markdown(f"**Asunto:** `{email_data['subject']}`")
        st.markdown(f"**De (From):** `{email_data['from']}`")
        st.markdown(f"**Ruta de Retorno (Return-Path):** `{email_data['return_path']}`")

        # Tarjetas de Validación de Autenticación
        st.markdown("#### 🔐 Verificación de Autenticación del Dominio")
        spf, dkim, dmarc = analyze_auth_headers(email_data["headers"])

        m_col1, m_col2, m_col3 = st.columns(3)
        m_col1.metric("SPF", spf, delta="Correcto" if spf == "PASS" else "Fallo / Inseguro",
                      delta_color="normal" if spf == "PASS" else "inverse")
        m_col2.metric("DKIM", dkim, delta="Firma Válida" if dkim == "PASS" else "Sin Firma / Fallo",
                      delta_color="normal" if dkim == "PASS" else "inverse")
        m_col3.metric("DMARC", dmarc, delta="Alineado" if dmarc == "PASS" else "Desalineado",
                      delta_color="normal" if dmarc == "PASS" else "inverse")

        # Detección de Spoofing
        st.markdown("#### 🚨 Análisis de Riesgo Preliminar")
        from_str = str(email_data['from'])
        return_path_str = str(email_data['return_path'])

        if return_path_str != "N/A" and return_path_str.strip("<>") not in from_str:
            st.error(
                "⚠️ **Spoofing Detectado:** La dirección 'From' no coincide con 'Return-Path'. El remitente real difiere de la identidad mostrada.")
        else:
            st.info("ℹ️ Remitente alineado aparentemente con Return-Path.")

        # Rastreo de IPs
        st.markdown("#### 🌐 Servidores / IPs Detectadas en Tránsito")
        extracted_ips = extract_ip_addresses(email_data["headers"])
        if extracted_ips:
            for ip in extracted_ips:
                st.code(f"IP de Origen/Tránsito: {ip}", language="text")
        else:
            st.write("No se identificaron IPs públicas en las cabeceras.")

        # Extracción de URLs e Integración VT
        raw_urls, defanged_urls = extract_urls(email_data["body"] + "\n" + email_data["headers"])

        st.markdown("#### 🔗 Enlaces Extraídos (Defanged / Seguros)")
        if defanged_urls:
            for idx, (raw_u, def_u) in enumerate(zip(raw_urls, defanged_urls)):
                st.warning(f"`{def_u}`")

                if vt_api_key:
                    if st.button(f"🔍 Consultar URL en VirusTotal", key=f"vt_btn_{idx}"):
                        with st.spinner("Consultando VirusTotal API..."):
                            res = check_vt_url(vt_api_key, raw_u)
                            if isinstance(res, dict):
                                st.write(
                                    f"**Resultados VT:** 🛑 Maliciosos: `{res.get('malicious', 0)}` | ⚠️ Sospechosos: `{res.get('suspicious', 0)}` | ✅ Limpios: `{res.get('harmless', 0)}`")
                            elif res == "NOT_FOUND":
                                st.info("URL no registrada previamente en VirusTotal.")
                            else:
                                st.error("Error al consultar la API de VirusTotal (verifica la API Key).")
        else:
            st.write("No se encontraron enlaces en la muestra.")