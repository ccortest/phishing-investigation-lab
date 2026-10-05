# 🛡️ Phishing Investigation & Email Header Analyzer

Una herramienta interactiva web desarrollada en Python con Streamlit para la investigación de incidentes de correo electrónico y análisis forense de encabezados MIME. Diseñada para analistas SOC y profesionales de ciberseguridad.

---

## 📋 ¿Qué hace esta herramienta?

Esta aplicación automatiza el proceso de triaje ante correos sospechosos realizando los siguientes análisis:

1. **Parsing de Archivos:** Extrae el asunto, remitente, ruta de retorno y cuerpo del correo desde archivos `.eml`, `.msg` o encabezados en texto plano.
2. **Validación de Autenticación de Dominio:** Analiza los encabezados para determinar el estado de los protocolos **SPF**, **DKIM** y **DMARC** (PASS / FAIL / UNKNOWN).
3. **Detección de Spoofing:** Compara la dirección del remitente (`From`) con la ruta de retorno (`Return-Path`) y genera una alerta visual si hay discrepancias de suplantación.
4. **Rastreo de Red (MIME Headers):** Analiza las líneas `Received:` de los encabezados para extraer y aislar las direcciones IP públicas por las que transitó el correo.
5. **Desarme de URLs (URL Defanging):** Sanitiza automáticamente los enlaces presentes en el cuerpo del correo (convirtiendo `http://` a `hxxp://` y `.` a `[.]`) para prevenir clics accidentales.
6. **Integración con Threat Intelligence:** Permite consultar la reputación de los enlaces extraídos en tiempo real utilizando la API v3 de VirusTotal.
7. **Protección de Credenciales:** Oculta la API Key de VirusTotal una vez ingresada y la mantiene guardada únicamente en memoria durante la sesión activa (`st.session_state`).

---

## 🛠️ Requisitos Previos

Antes de ejecutar el proyecto, asegúrate de tener instalado:

* **Python 3.10** o superior.
* **Git** (para clonar el repositorio).
* Una cuenta en **VirusTotal** (opcional, para obtener la API key gratuita).

---

## 🚀 Guía de Instalación Paso a Paso

### 1. Clonar el repositorio
Abre tu terminal o consola de comandos y ejecuta:

git clone https://github.com/tu-usuario/phishing-header-analyzer.git
cd phishing-header-analyzer

### 2. Crear y activar un entorno virtual (Recomendado)

* **Windows (PowerShell / CMD):**
  python -m venv venv
  .\venv\Scripts\activate

* **Linux / macOS:**
  python3 -m venv venv
  source venv/bin/activate

### 3. Instalar las dependencias necesarias

pip install -r requirements.txt

### 4. Ejecutar la aplicación

streamlit run app.py

La aplicación se abrirá automáticamente en tu navegador predeterminado en la dirección `http://localhost:8501`.

---

## 🖥️ Manual de Uso de la Aplicación

1. **Ingresar la API Key de VirusTotal (Opcional):**
   * Ve a la barra lateral izquierda (`⚙️ Configuración & API Keys`).
   * Pega tu API Key de VirusTotal y presiona `Enter`.
   * El sistema la guardará en memoria, ocultará la clave por seguridad y mostrará el indicador `🟢 API Key Cargada (En memoria)`.

2. **Cargar la Evidencia de Correo:**
   * En la columna izquierda (`📥 Cargar Evidencia`), haz clic en **Browse files** para subir un archivo `.eml` o `.msg`.
   * También puedes pegar directamente los encabezados completos en texto plano en la caja de texto.

3. **Revisar el Análisis del Incidente:**
   * En la columna derecha (`🔍 Resumen Visual del Incidente`) verás:
     * **Metadatos principales:** Asunto, From y Return-Path.
     * **Tarjetas SPF / DKIM / DMARC:** Indicadores visuales en verde/rojo según el resultado del análisis.
     * **Alertas de Spoofing:** Notificación resaltada en rojo si el origen no coincide.
     * **IPs Detectadas:** Lista de direcciones IP públicas de tránsito.
     * **URLs Sanitizadas:** Enlaces desarmados listos para revisar.

4. **Consultar Amenazas en VirusTotal:**
   * Junto a cada URL desarmada, haz clic en el botón `🔍 Consultar URL en VirusTotal` para obtener las métricas de detección (Maliciosos, Sospechosos, Limpios).

---

## 🔒 Estructura del Proyecto

```text
phishing-header-analyzer/
├── app.py              # Código principal de la aplicación Streamlit
├── requirements.txt    # Lista de librerías de Python requeridas
├── README.md           # Documentación del proyecto
└── .gitignore          # Archivos excluidos del control de versiones
```