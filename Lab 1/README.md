# Laboratorio 1 - Criptografía y Stealth ICMP

### Descripción

Este laboratorio simula el tráfico de ping y la vulnerabilidad del cifrado César frente a ataques de fuerza bruta. Para esto, se desarrollaron 3 scripts en Python implementando:

1. Cifrado César  de un mensaje.
2. Envío encubierto del mensaje cifrado (un carácter por paquete ICMP).
3. Captura del tráfico y descifrado por fuerza bruta.

### Estructura del Repositorio

Lab 1/
├── cesar.py              # Script de cifrado César
├── stealth.py            # Script de envío ICMP stealth
├── mitm.py               # Script de captura y descifrado
├── captura.pcapng        # Captura de tráfico de ejemplo (Wireshark)
└── README.md             # Este archivo

### Requisitos

- Python 3.x
- Bibliotecas Python: scapy
- Permisos de administrador (para enviar/capturar paquetes)

```bash
pip install scapy
```

### Uso

1. Cifrar un Mensaje César
```bash
python3 cesar.py "Mensaje de prueba" 6
```

Salida:
```bash
Sktygpk jk vxakhg
```

2. Enviar Mensaje Cifrado via ICMP Stealth
```bash
sudo python3 stealth.py "Sktygpk jk vxakhg"
```
El script enviará cada carácter como un paquete ICMP individual a 8.8.8.8.

3. Capturar y Descifrar el Mensaje
Captura el tráfico con Wireshark o tcpdump, guárdalo como captura.pcapng, y luego:
```bash
sudo python3 mitm.py captura.pcapng
```
El script intentará todos los corrimientos del cifrado César y destacará el mensaje más probable.

### Resultados Esperados

- Desplazamiento 6 convierte "Mensaje de prueba" en "Sktygpk jk vxakhg".
- Paquetes con payload de 1 byte (caracteres cifrados) similares a pings legítimos.
- Fuerza bruta identifica el corrimiento 6 y recupera el mensaje original.
