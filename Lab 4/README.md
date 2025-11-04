# Laboratorio 4

###### Diego Muñoz Barra - Sección 2

### Objetivo

Este proyecto implementa un script en Python que usa la librería pycryptodome para cifrar y descifrar mensajes empleando 3 algoritmos de cifrado simétrico:

1. DES (Data Enctryption Standard)
2. AES-256 (Advanced Encryption Standard)
3. 3DES (Triple DES)

Ajusta automáticamente el tamaño de la clave e IV según el algoritmo usado, realizando las operaciones de cifrado y descifrado en modo CBC (Cipher Block Chaining).

Incluye además una pequeña guía para comparar los resultados con el servicio online (en este caso CyberChef). 

```
https://gchq.github.io/CyberChef/
```

### Requisitos 

- Python 3.8+
- Librería pycryptodome

Instalación de dependencias:

```
pip install pycryptodome
```

### Ejecución

1. Clonar o copiar el archivo .py
2. Ejecutar el archivo
3. Ingresar:
    - Texto a cifrar
    - Clave
    - Vector de inicialización IV
4. Observar resultados para DES, AES-256 y 3DES



```
=== PROGRAMA DE CIFRADO SIMÉTRICO ===
Algoritmos disponibles: DES, AES-256, 3DES

Ingrese el texto a cifrar: texto
Ingrese la clave: clave
Ingrese el vector de inicialización (IV): vector

============================================================

--- CIFRADO DES ---
Clave complementada con 3 bytes aleatorios
IV complementado con 2 bytes aleatorios
Clave final DES (hex): 636c617665aea556
IV final DES (hex): 766563746f72ae0f
Texto cifrado (DES): Z0feEDm4y8w=
Texto descifrado (DES): texto
```

