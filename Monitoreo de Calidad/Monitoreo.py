import csv
from collections import defaultdict

def evaluar_qos_routers(ruta_csv, ruta_reporte):
    """
    Lee métricas de routers desde un CSV y genera un reporte de cumplimiento de SLA.
    """
    # Diccionario anidado para agrupar múltiples métricas por Router ID
    metricas_router = defaultdict(lambda: {
        'suma_latencia': 0.0,
        'total_muestras': 0,
        'paquetes_enviados': 0,
        'paquetes_perdidos': 0,
        'estados': defaultdict(int)
    })

    try:
        # Lectura eficiente con manejo de bloque (Evita saturar memoria)
        with open(ruta_csv, mode='r', encoding='utf-8') as archivo_csv:
            lector = csv.reader(archivo_csv)
            encabezados = next(lector, None) # Saltar la primera línea (cabeceras)
            
            for fila in lector:
                # Validar que la fila tenga exactamente 7 columnas
                if len(fila) < 7:
                    continue
                
                id_router = fila[1]
                estado_enlace = fila[6].strip().upper()
                
                # Extracción y casteo de datos numéricos
                try:
                    latencia = float(fila[3])
                    p_enviados = int(fila[4])
                    p_perdidos = int(fila[5])
                except ValueError:
                    continue # Ignorar filas con datos corruptos
                
                # Acumulación de valores en la estructura de datos
                metricas_router[id_router]['suma_latencia'] += latencia
                metricas_router[id_router]['total_muestras'] += 1
                metricas_router[id_router]['paquetes_enviados'] += p_enviados
                metricas_router[id_router]['paquetes_perdidos'] += p_perdidos
                metricas_router[id_router]['estados'][estado_enlace] += 1

    except FileNotFoundError:
        print(f"Error: El archivo {ruta_csv} no existe.")
        return

    # Procesamiento y generación del reporte final
    with open(ruta_reporte, mode='w', encoding='utf-8') as reporte:
        reporte.write("=== REPORTE DE CALIDAD DE SERVICIO (QoS) Y SLA ===\n\n")

        for router, datos in metricas_router.items():
            muestras = datos['total_muestras']
            if muestras == 0:
                continue

            # Cálculos de precisión en ingeniería
            latencia_promedio = datos['suma_latencia'] / muestras
            
            total_env = datos['paquetes_enviados']
            total_perd = datos['paquetes_perdidos']
            porcentaje_perdida = (total_perd / total_env) * 100 if total_env > 0 else 0
            
            veces_down = datos['estados'].get('DOWN', 0)
            porcentaje_down = (veces_down / muestras) * 100

            # Lógica de violación de SLA (Latencia > 150ms o Pérdida > 5%)
            viola_sla = latencia_promedio > 150 or porcentaje_perdida > 5

            # Escritura formateada
            reporte.write(f"ROUTER: {router}\n")
            reporte.write(f"  - Latencia Promedio: {latencia_promedio:.2f} ms\n")
            reporte.write(f"  - Pérdida de Paquetes: {porcentaje_perdida:.2f}%\n")
            reporte.write(f"  - Inactividad (DOWN): {porcentaje_down:.2f}%\n")
            
            if viola_sla:
                reporte.write("  - ESTADO: [ALERTA] Violación de SLA detectada.\n")
            else:
                reporte.write("  - ESTADO: [OK] Cumple SLA.\n")
                
            reporte.write("-" * 45 + "\n")

    print(f"Ejercicio 2 finalizado. Reporte guardado en: {ruta_reporte}")

# Ejecución
evaluar_qos_routers('router_metrics.csv', 'reporte_qos_sla.txt')