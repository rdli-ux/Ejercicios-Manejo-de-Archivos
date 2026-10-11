import os
from collections import defaultdict

def formatear_bytes(bytes_totales):
    """Convierte la cantidad de bytes a una unidad legible (KB, MB, GB)."""
    if bytes_totales >= 1024**3:
        return f"{bytes_totales / (1024**3):.2f} GB"
    elif bytes_totales >= 1024**2:
        return f"{bytes_totales / (1024**2):.2f} MB"
    elif bytes_totales >= 1024:
        return f"{bytes_totales / 1024:.2f} KB"
    return f"{bytes_totales} B"

def generar_reporte_seguridad(ruta_log, ruta_reporte, umbral_fuerza_bruta=50):
    """
    Lee el log de red línea por línea, extrae métricas de seguridad y exporta un reporte.
    """
    # Uso de diccionarios para agrupar acumulados (Buenas prácticas y Estructuras de datos)
    top_talkers = defaultdict(int)
    alertas_denegadas = defaultdict(int)
    conteo_protocolos = defaultdict(int)
    total_lineas_validas = 0

    try:
        # Lectura eficiente línea por línea sin cargar todo en memoria
        with open(ruta_log, 'r', encoding='utf-8') as archivo_log:
            for linea in archivo_log:
                columnas = linea.strip().split()
                
                # Validación para evitar líneas incompletas (Parseo y Extracción)
                if len(columnas) < 7:
                    continue
                
                ip_origen = columnas[1]
                puerto_destino = columnas[3]
                protocolo = columnas[4]
                accion = columnas[5]
                
                try:
                    bytes_transferidos = int(columnas[6])
                except ValueError:
                    continue # Omite la línea si los bytes no son un número válido

                total_lineas_validas += 1
                conteo_protocolos[protocolo] += 1
                
                # Lógica de Top Talkers: Solo contabilizar tráfico permitido
                if accion == 'ALLOW':
                    top_talkers[ip_origen] += bytes_transferidos
                
                # Lógica de Fuerza Bruta: Accesos denegados a SSH (22) o RDP (3389)
                if accion == 'DENY' and puerto_destino in ['22', '3389']:
                    alertas_denegadas[ip_origen] += 1

    except FileNotFoundError:
        print(f"Error: El archivo {ruta_log} no existe.")
        return

    # Precisión matemática y ordenamiento
    top_5_ips = sorted(top_talkers.items(), key=lambda x: x[1], reverse=True)[:5]
    ips_sospechosas = {ip: conteo for ip, conteo in alertas_denegadas.items() if conteo > umbral_fuerza_bruta}

    # Generación del archivo de salida estructurado
    with open(ruta_reporte, 'w', encoding='utf-8') as reporte:
        reporte.write("=== REPORTE DE DIAGNÓSTICO DE RED ===\n")
        reporte.write(f"Total de registros procesados: {total_lineas_validas}\n\n")
        
        reporte.write("--- TOP 5 IP ORIGEN POR VOLUMEN DE DATOS (ALLOW) ---\n")
        for i, (ip, total_bytes) in enumerate(top_5_ips, 1):
            reporte.write(f"{i}. IP: {ip:<15} | Tráfico: {formatear_bytes(total_bytes)}\n")
            
        reporte.write("\n--- ALERTAS DE SEGURIDAD (FUERZA BRUTA) ---\n")
        if ips_sospechosas:
            for ip, conteo in ips_sospechosas.items():
                reporte.write(f"[ALERTA] IP: {ip} registró {conteo} intentos fallidos a puertos críticos.\n")
        else:
            reporte.write("No se detectaron anomalías que superen el umbral.\n")
            
        reporte.write("\n--- DISTRIBUCIÓN DE PROTOCOLOS ---\n")
        for protocolo, conteo in conteo_protocolos.items():
            porcentaje = (conteo / total_lineas_validas) * 100
            reporte.write(f"- {protocolo}: {porcentaje:.2f}%\n")

    print(f"Ejercicio 1 finalizado. Reporte guardado en: {ruta_reporte}")

# Ejecución
generar_reporte_seguridad('network_traffic.log', 'reporte_diagnostico.txt')