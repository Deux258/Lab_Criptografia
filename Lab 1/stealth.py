import sys
import subprocess
from scapy.all import IP, ICMP, send

def send_stealth_ping(message, dest_ip="8.8.8.8"):
    """
    Envía un carácter por paquete ICMP echo request.
    """
    for char in message:
        # Construye el paquete ICMP con el carácter como dato
        packet = IP(dst=dest_ip)/ICMP()/char
        send(packet, verbose=False)
        print(f"Sent 1 packet")

def run_real_ping(dest_ip="8.8.8.8"):
    """
    Ejecuta un comando ping real y muestra la salida.
    """
    print(f"\nEjecutando ping real hacia {dest_ip}:")
    result = subprocess.run(['ping', '-c', '1', dest_ip], capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print("Error:", result.stderr)

if __name__ == "__main__":
    # Verificar permisos de root
    if not subprocess.run(['id', '-u'], capture_output=True, text=True).stdout.strip() == '0':
        print("Este programa requiere permisos de root. Ejecuta con sudo.")
        sys.exit(1)

    # Verificar argumentos
    if len(sys.argv) != 2:
        print("Uso: sudo python3 pingv4.py <mensaje>")
        sys.exit(1)

    message = sys.argv[1]
    dest_ip = "8.8.8.8"  # Puedes cambiar la IP destino si es necesario

    # Mostrar ping real antes
    run_real_ping(dest_ip)

    # Enviar paquetes stealth
    print(f"\nEnviando paquetes stealth con mensaje: '{message}'")
    send_stealth_ping(message, dest_ip)

    # Mostrar ping real después
    run_real_ping(dest_ip)