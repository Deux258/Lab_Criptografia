from scapy.all import rdpcap, ICMP, IP
import sys

def descifrar_cesar(texto, corrimiento):
    """Descifra un texto con corrimiento César."""
    resultado = ""
    for caracter in texto:
        if caracter.isalpha():
            base = ord('A') if caracter.isupper() else ord('a')
            resultado += chr((ord(caracter) - base - corrimiento) % 26 + base)
        else:
            resultado += caracter
    return resultado

def extraer_mensaje(pcap_file):
    """Lee un .pcapng y reconstruye el mensaje a partir del campo Data de ICMP."""
    paquetes = rdpcap(pcap_file)
    mensaje = ""

    for pkt in paquetes:
        # Verificar si es un paquete ICMP echo request (tipo 8)
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
            # Obtener la capa ICMP
            icmp_layer = pkt[ICMP]
            
            # Extraer el campo Data (carga útil de ICMP)
            if hasattr(icmp_layer, 'load'):
                data = icmp_layer.load
                if data:
                    # Tomar solo el primer byte del campo Data
                    try:
                        char = data[0:1].decode('utf-8')
                        if char.isprintable():
                            mensaje += char
                    except UnicodeDecodeError:
                        # Si no se puede decodificar, saltar este byte
                        continue
    
    return mensaje

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: sudo python3 mith.py <archivo.pcapng>")
        sys.exit(1)
    
    archivo = sys.argv[1]
    
    try:
        mensaje_cifrado = extraer_mensaje(archivo)
    except Exception as e:
        print(f"Error al procesar el archivo: {e}")
        sys.exit(1)
        
    print(f"\nMensaje capturado (cifrado): {mensaje_cifrado}\n")
    print("Posibles descifrados con corrimientos de 0 a 25:\n")

    for corrimiento in range(26):
        mensaje_descifrado = descifrar_cesar(mensaje_cifrado, corrimiento)
        print(f"Corrimiento {corrimiento:2d}: {mensaje_descifrado}")