import sys

def cesar_encrypt(text, shift):
    """
    Cifra un texto usando el algoritmo César.
    
    Args:
        text (str): Texto a cifrar
        shift (int): Desplazamiento para el cifrado
    
    Returns:
        str: Texto cifrado
    """
    result = []
    shift = shift % 26  # Manejar desplazamientos mayores a 26
    
    for char in text:
        if char.isalpha():
            # Determinar la base (minúscula o mayúscula)
            base = ord('a') if char.islower() else ord('A')
            # Aplicar el desplazamiento
            encrypted_char = chr((ord(char) - base + shift) % 26 + base)
            result.append(encrypted_char)
        else:
            # Mantener caracteres no alfabéticos sin cambios
            result.append(char)
    
    return ''.join(result)

def main():
    # Verificar número de argumentos
    if len(sys.argv) != 3:
        print("Uso: python3 cesar.py <texto> <desplazamiento>")
        sys.exit(1)
    
    # Obtener argumentos
    text = sys.argv[1]
    try:
        shift = int(sys.argv[2])
    except ValueError:
        print("El desplazamiento debe ser un número entero")
        sys.exit(1)
    
    # Cifrar y mostrar resultado
    encrypted_text = cesar_encrypt(text, shift)
    print(encrypted_text)

if __name__ == "__main__":
    main()