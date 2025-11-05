from Crypto.Cipher import DES, AES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# =============================================================================
# INVESTIGACIÓN PREVIA
# =============================================================================
"""
ALGORITMOS DE CIFRADO SIMÉTRICO:

DES (Data Encryption Standard):
- Tamaño clave: 8 bytes (64 bits)
- Tamaño IV: 8 bytes (64 bits)
- Tamaño bloque: 64 bits
- Seguridad: Baja, vulnerable a ataques de fuerza bruta
- Velocidad: Rápido

AES-256 (Advanced Encryption Standard):
- Tamaño clave: 32 bytes (256 bits)
- Tamaño IV: 16 bytes (128 bits)
- Tamaño bloque: 128 bits
- Seguridad: Alta, considerado seguro
- Velocidad: Rápido

3DES (Triple DES):
- Tamaño clave: 24 bytes (192 bits)
- Tamaño IV: 8 bytes (64 bits)
- Tamaño bloque: 64 bits
- Seguridad: Media, mejor que DES pero más lento que AES
- Velocidad: Lento (tres operaciones DES)

PRINCIPALES DIFERENCIAS:
1. Seguridad: AES-256 > 3DES > DES
2. Velocidad: AES-256 ≈ DES > 3DES
3. Tamaño de clave: AES-256 (256 bits) > 3DES (192 bits) > DES (64 bits)
"""

# =============================================================================
# FUNCIONES DE AJUSTE DE CLAVE Y IV
# =============================================================================

def cifrar_clave(clave_ingresada, algoritmo):
    
    #Ajusta la clave al tamaño requerido por el algoritmo
    
    if algoritmo == 'DES': tam_requerido = 8
    elif algoritmo == 'AES-256': tam_requerido = 32
    elif algoritmo == '3DES': tam_requerido = 24
    else: raise ValueError("Algoritno no soportado")
    
    clave_bytes = clave_ingresada.encode('utf-8')
    
    if len(clave_bytes) < tam_requerido:

        # Si la clave en bytes es menor al tamaño requerido, rellena aleatoriamente

        bytes_faltantes = tam_requerido - len(clave_bytes)
        clave_bytes += get_random_bytes(bytes_faltantes)

        print(f"Clave complementada con {bytes_faltantes} bytes aleatorios")

    elif len(clave_bytes) > tam_requerido:
        
        # Si la clave es mayor que la requerida, truncamos 

        clave_bytes = clave_bytes[:tam_requerido]
        print(f"Clave truncada a {tam_requerido} bytes")
    
    return clave_bytes

def ajustar_iv(iv_ingresado, algoritmo):
    
    #Ajusta el IV al tamaño requerido por el algoritmo
    
    if algoritmo == 'DES' or algoritmo == '3DES':
        tam_requerido = 8
    elif algoritmo == 'AES-256':
        tam_requerido = 16
    else:
        raise ValueError("Algoritno no soportado")
    
    iv_bytes = iv_ingresado.encode('utf-8')
    
    if len(iv_bytes) < tam_requerido:

        bytes_faltantes = tam_requerido - len(iv_bytes)
        iv_bytes += get_random_bytes(bytes_faltantes)

        print(f"IV complementado con {bytes_faltantes} bytes aleatorios")

    elif len(iv_bytes) > tam_requerido:
        
        iv_bytes = iv_bytes[:tam_requerido]
        print(f"IV truncado a {tam_requerido} bytes")
    
    return iv_bytes

# =============================================================================
# FUNCIONES DE CIFRADO Y DESCIFRADO
# =============================================================================

def cifrar_des(clave, iv, texto):
    cipher = DES.new(clave, DES.MODE_CBC, iv)
    t_bytes = texto.encode('utf-8')
    padding = pad(t_bytes, DES.block_size)
    t_cifrado = cipher.encrypt(padding)
    #return base64.b64encode(t_cifrado).decode('utf-8')
    return t_cifrado.hex()

def descifrar_des(clave, iv, t_cifrado):
    cipher = DES.new(clave, DES.MODE_CBC, iv)
    t_cifrado_bytes = bytes.fromhex(t_cifrado)
    t_descifrado = cipher.decrypt(t_cifrado_bytes)
    texto_original = unpad(t_descifrado, DES.block_size)
    #return texto_original.decode('utf-8')
    return texto_original.decode('utf-8')

def cifrar_aes256(clave, iv, texto):
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    t_bytes = texto.encode('utf-8')
    padding = pad(t_bytes, AES.block_size)
    t_cifrado = cipher.encrypt(padding)
    #return base64.b64encode(t_cifrado).decode('utf-8')
    return t_cifrado.hex()

def descifrar_aes256(clave, iv, t_cifrado):
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    t_cifrado_bytes = bytes.fromhex(t_cifrado)
    t_descifrado = cipher.decrypt(t_cifrado_bytes)
    #texto_original = unpad(t_descifrado, AES.block_size)
    #return texto_original.decode('utf-8')
    return unpad(t_descifrado, AES.block_size).decode('utf-8')

def cifrar_3des(clave, iv, texto):
    cipher = DES3.new(clave, DES3.MODE_CBC, iv)
    t_bytes = texto.encode('utf-8')
    padding = pad(t_bytes, DES3.block_size)
    t_cifrado = cipher.encrypt(padding)
    return t_cifrado.hex()

def descifrar_3des(clave, iv, t_cifrado):
    cipher = DES3.new(clave, DES3.MODE_CBC, iv)
    t_cifrado_bytes = bytes.fromhex(t_cifrado)
    t_descifrado = cipher.decrypt(t_cifrado_bytes)
    return unpad(t_descifrado, DES3.block_size).decode('utf-8')

# =============================================================================
# FUNCION PRINCIPAL
# =============================================================================

def main():
    print("=== PROGRAMA DE CIFRADO SIMÉTRICO ===")
    print("Algoritmos disponibles: DES, AES-256, 3DES")
    print()
    
    # Inputs solicitados al usuario
    texto = input("Ingrese el texto a cifrar: ")
    clave = input("Ingrese la clave: ")
    iv = input("Ingrese el vector de inicialización (IV): ")
    
    print("\n" + "="*60)
    
    print("\n--- CIFRADO DES ---")

    clave_des = cifrar_clave(clave, 'DES')
    iv_des = ajustar_iv(iv, 'DES')
    
    print(f"Clave final DES (hex): {clave_des.hex()}")
    print(f"IV final DES (hex): {iv_des.hex()}")
    
    t_cifrado_des = cifrar_des(clave_des, iv_des, texto)
    t_descifrado_des = descifrar_des(clave_des, iv_des, t_cifrado_des)
    
    print(f"Texto cifrado (DES): {t_cifrado_des}")
    print(f"Texto descifrado (DES): {t_descifrado_des}")
    
    # Procesar para AES-256
    print("\n--- CIFRADO AES-256 ---")
    clave_aes = cifrar_clave(clave, 'AES-256')
    iv_aes = ajustar_iv(iv, 'AES-256')
    print(f"Clave final AES-256 (hex): {clave_aes.hex()}")
    print(f"IV final AES-256 (hex): {iv_aes.hex()}")
    
    t_cifrado_aes = cifrar_aes256(clave_aes, iv_aes, texto)
    t_descifrado_aes = descifrar_aes256(clave_aes, iv_aes, t_cifrado_aes)
    
    print(f"Texto cifrado (AES-256): {t_cifrado_aes}")
    print(f"Texto descifrado (AES-256): {t_descifrado_aes}")
    
    # Procesar para 3DES
    print("\n--- CIFRADO 3DES ---")
    clave_3des = cifrar_clave(clave, '3DES')
    iv_3des = ajustar_iv(iv, '3DES')
    print(f"Clave final 3DES (hex): {clave_3des.hex()}")
    print(f"IV final 3DES (hex): {iv_3des.hex()}")
    
    t_cifrado_3des = cifrar_3des(clave_3des, iv_3des, texto)
    t_descifrado_3des = descifrar_3des(clave_3des, iv_3des, t_cifrado_3des)
    
    print(f"Texto cifrado (3DES): {t_cifrado_3des}")
    print(f"Texto descifrado (3DES): {t_descifrado_3des}")
    
    # =========================================================================
    # COMPARACIÓN CON SERVICIO ONLINE
    # =========================================================================
    print("\n" + "="*60)
    print("COMPARACIÓN CON SERVICIO ONLINE")
    print("="*60)
    
    print("\nPara verificar con un servicio online (ej: CyberChef):")
    print("Algoritmo seleccionado para comparación: AES-256")

    print(f"1. Ingresa el texto original en 'Input': {texto}")
    print("2. Busca 'AES Encrypt' en operaciones")
    print("3. Configura:")
    print("   - Key: " + clave_aes.hex())
    print("   - IV: " + iv_aes.hex())
    print("   - Mode: CBC")
    print("   - Input: Raw")
    print("   - Output: Hex")
    print(f"4. Texto cifrado esperado: {t_cifrado_aes}")
    print("El resultado debe coincidir con el texto cifrado arriba")

if __name__ == "__main__":
    main()