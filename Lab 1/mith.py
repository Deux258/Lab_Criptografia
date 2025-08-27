import sys
from scapy.all import sniff, ICMP
import re

# Lista de palabras comunes en español para detección
PALABRAS_COMUNES_ES = {
    'el', 'la', 'los', 'las', 'de', 'en', 'y', 'a', 'que', 'es', 'por', 'para', 
    'con', 'se', 'su', 'al', 'lo', 'como', 'más', 'pero', 'sus', 'le', 'ha', 
    'me', 'si', 'sin', 'sobre', 'este', 'ya', 'entre', 'cuando', 'todo', 'esta', 
    'ser', 'son', 'dos', 'también', 'fue', 'había', 'era', 'muy', 'años', 'hasta', 
    'desde', 'está', 'mi', 'porque', 'qué', 'sólo', 'he', 'hay', 'vez', 'puede', 
    'todos', 'así', 'ni', 'parte', 'tiene', 'él', 'uno', 'donde', 'bien', 'tiempo', 
    'mismo', 'ese', 'ahora', 'cada', 'e', 'vida', 'otro', 'después', 'te', 'otros', 
    'aunque', 'esa', 'eso', 'hace', 'otra', 'gobierno', 'tan', 'durante', 'siempre', 
    'día', 'tanto', 'ella', 'tres', 'sí', 'dijo', 'sido', 'gran', 'país', 'según', 
    'menos', 'mundo', 'año', 'antes', 'estado', 'contra', 'sino', 'forma', 'caso', 
    'nada', 'hacer', 'general', 'estaba', 'poco', 'estos', 'presidente', 'mayor', 
    'ante', 'unos', 'les', 'algo', 'hacia', 'casa', 'ellos', 'ayer', 'hecho', 'primera', 
    'mucho', 'mientras', 'además', 'quien', 'momento', 'millones', 'esto', 'espacio', 
    'no', 'ustedes', 'tierra', 'igual', 'política', 'personas', 'gestión', 'siendo', 
    'libro', 'trabajo', 'punto', 'ciudad', 'social', 'casi', 'toda', 'medio', 'va', 
    'están', 'cómo', 'han', 'pues', 'nunca', 'aquí', 'mano', 'estar', 'san', 'noche', 
    'días', 'alguien', 'señor', 'pasado', 'primer', 'ejemplo', 'acuerdo', 'haber', 
    'ti', 'cosa', 'fin', 'cual', 'cuerpo', 'presente', 'poder', 'obras', 'grupo', 
    'dinero', 'serie', 'zona', 'tipo', 'carácter', 'four', 'lugar', 'tal', 'semana', 
    'allí', 'hola', 'mundo', 'adiós', 'gracias', 'por favor', 'saludos', 'gracias', 
    'gracias', 'nombre', 'edad', 'dirección', 'teléfono', 'correo', 'fecha', 'hora'
}

def cesar_decrypt(ciphertext, shift):
    """
    Descifra un texto usando el cifrado César con un desplazamiento dado.
    """
    decrypted = []
    for char in ciphertext:
        if char.isalpha():
            base = ord('a') if char.islower() else ord('A')
            decrypted_char = chr((ord(char) - base - shift) % 26 + base)
            decrypted.append(decrypted_char)
        else:
            decrypted.append(char)
    return ''.join(decrypted)

def contains_spanish_words(text):
    """
    Verifica si el texto contiene palabras comunes en español.
    """
    words = re.findall(r'\b\w+\b', text.lower())
    common_word_count = sum(1 for word in words if word in PALABRAS_COMUNES_ES)
    return common_word_count > len(words) * 0.2  # Al menos 20% de palabras comunes

def packet_callback(packet):
    """
    Callback para procesar cada paquete capturado.
    """
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:
        data = bytes(packet[ICMP].payload).decode('utf-8', errors='ignore')
        if data.strip():
            print(f"\nCaptured ICMP packet with data: {repr(data)}")
            print("Trying all Caesar shifts...")
            best_match = None
            best_score = 0
            results = []
            
            for shift in range(26):
                decrypted = cesar_decrypt(data, shift)
                results.append((shift, decrypted))
                # Calcular puntuación basada en palabras comunes
                score = sum(1 for word in re.findall(r'\b\w+\b', decrypted.lower()) if word in PALABRAS_COMUNES_ES)
                if score > best_score:
                    best_score = score
                    best_match = (shift, decrypted)
            
            # Imprimir todos los resultados
            for shift, decrypted in results:
                if best_match and shift == best_match[0]:
                    # Destacar en verde el mejor resultado
                    print(f"\033[92mShift {shift:2d}: {decrypted}\033[0m")
                else:
                    print(f"Shift {shift:2d}: {decrypted}")
            
            if best_match:
                print(f"\nMost likely shift: {best_match[0]} (score: {best_score})")
            else:
                print("No likely Spanish text found.")

def main():
    """
    Función principal para capturar paquetes ICMP.
    """
    print("Starting ICMP packet capture... Press Ctrl+C to stop.")
    print("Listening for ICMP echo requests (type 8)...")
    # Filtro para capturar solo ICMP echo requests
    sniff(filter="icmp and icmp[0] == 8", prn=packet_callback, store=0)

if __name__ == "__main__":
    # Verificar que se ejecute como root
    if not sys.platform.startswith('win') and os.geteuid() != 0:
        print("This program requires root privileges. Run with sudo.")
        sys.exit(1)
    
    main()