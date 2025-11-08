"""
Sistema RSA - Encriptación con Teoría de Números
Implementa conceptos de los capítulos 4.1 y 4.3
"""

import random

# Lista de los primeros 25 números primos
PRIMOS = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 
          53, 59, 61, 67, 71, 73, 79, 83, 89, 97]


# Algoritmo de Euclides para calcular MCD
def mcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


# Algoritmo Extendido de Euclides para encontrar el inverso modular
def mcd_extendido(a, b):
    if b == 0:
        return a, 1, 0
    mcd_val, x1, y1 = mcd_extendido(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return mcd_val, x, y


# Calcula d tal que: e * d ≡ 1 (mod phi_n)
def inverso_modular(e, phi_n):
    mcd_val, x, y = mcd_extendido(e, phi_n)
    if mcd_val != 1:
        return None
    return x % phi_n


# Test de primalidad por división
def es_primo(n):
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


# Exponenciación modular: (base^exp) mod m
# Usa la propiedad: (a * b) mod m = [(a mod m) * (b mod m)] mod m
def exp_modular(base, exp, mod):
    resultado = 1
    base = base % mod
    
    while exp > 0:
        if exp % 2 == 1:
            resultado = (resultado * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    
    return resultado


# Genera las claves RSA a partir de dos primos p y q
def generar_claves(p, q):
    # Verificar que ambos sean primos
    if not es_primo(p):
        print(f"Error: {p} no es un numero primo")
        return None
    
    if not es_primo(q):
        print(f"Error: {q} no es un numero primo")
        return None
    
    if p == q:
        print("Error: p y q deben ser diferentes")
        return None
    
    # Calculo de n (modulo)
    n = p * q
    
    # n debe ser mayor a 127 para poder encriptar ASCII
    if n < 128:
        print(f"Error: n = {n} es muy pequeno (necesita ser > 127)")
        return None
    
    # Calculo de la funcion de Euler: φ(n) = (p-1)(q-1)
    phi_n = (p - 1) * (q - 1)
    
    # Seleccionar e tal que 1 < e < φ(n) y MCD(e, φ(n)) = 1
    # Valores comunes: 3, 17, 65537
    e = 65537
    if e >= phi_n:
        e = 17
    if e >= phi_n:
        e = 3
    
    # Verificar que MCD(e, φ(n)) = 1
    while mcd(e, phi_n) != 1:
        e += 2
        if e >= phi_n:
            print("Error: No se pudo encontrar un exponente valido")
            return None
    
    # Calcular d usando el Algoritmo Extendido de Euclides
    # d es el inverso modular de e: e * d ≡ 1 (mod φ(n))
    d = inverso_modular(e, phi_n)
    
    if d is None:
        print("Error: No se pudo calcular la clave privada")
        return None
    
    print("\n" + "="*50)
    print("CLAVES GENERADAS")
    print("="*50)
    print(f"n = {p} x {q} = {n}")
    print(f"φ(n) = ({p}-1) x ({q}-1) = {phi_n}")
    print(f"e = {e}")
    print(f"{e} x {d} ≡ 1 (mod {phi_n})")
    print(f"d = {d}")
    print()
    print(f"Clave PUBLICA:  (e={e}, n={n})")
    print(f"Clave PRIVADA:  (d={d}, n={n})")
    print("="*50)
    print("\nNOTA: Anote estas claves, el programa NO las guardara")


# Encripta un mensaje usando la clave publica ingresada por el usuario
def encriptar(mensaje):
    try:
        entrada = input("\nIngrese la clave publica (e n): ").strip().split()
        e = int(entrada[0])
        n = int(entrada[1])
    except (ValueError, IndexError):
        print("Error: Formato invalido. Use: e n (ejemplo: 17 3233)")
        return None
    
    # Convertir cada caracter a su codigo ASCII
    codigos = [ord(c) for c in mensaje]
    
    # Aplicar la formula: c = m^e mod n
    cifrados = []
    for m in codigos:
        c = exp_modular(m, e, n)
        cifrados.append(c)
    
    print("\n" + "="*50)
    print("MENSAJE ENCRIPTADO")
    print("="*50)
    print(f"Usando clave publica: (e={e}, n={n})")
    print(f"Mensaje: {mensaje}")
    print(f"Cifrado: {cifrados}")
    print("="*50)
    
    return cifrados


# Desencripta un mensaje cifrado usando la clave privada ingresada por el usuario
def desencriptar(cifrados):
    try:
        entrada = input("\nIngrese la clave privada (d n): ").strip().split()
        d = int(entrada[0])
        n = int(entrada[1])
    except (ValueError, IndexError):
        print("Error: Formato invalido. Use: d n (ejemplo: 2753 3233)")
        return None
    
    # Aplicar la formula: m = c^d mod n
    descifrados = []
    for c in cifrados:
        m = exp_modular(c, d, n)
        descifrados.append(m)
    
    # Convertir codigos ASCII a caracteres
    mensaje = ''.join([chr(m) for m in descifrados])
    
    print("\n" + "="*50)
    print("MENSAJE DESENCRIPTADO")
    print("="*50)
    print(f"Usando clave privada: (d={d}, n={n})")
    print(f"Cifrado: {cifrados}")
    print(f"Mensaje: {mensaje}")
    print("="*50)
    
    return mensaje


def menu():
    while True:
        print("\n" + "="*50)
        print("SISTEMA RSA - ENCRIPTACION")
        print("="*50)
        print("\n1. Generar claves (ingresar p, q)")
        print("2. Encriptar mensaje")
        print("3. Desencriptar mensaje")
        print("4. Salir")
        print("="*50)
        
        opcion = input("\nSeleccione una opcion: ").strip()
        
        if opcion == "1":
            print("\n" + "-"*50)
            print("1. Ingresar dos numeros primos manualmente")
            print("2. Elegir de la lista de primos disponibles")
            print("-"*50)
            
            sub_opcion = input("Seleccione metodo: ").strip()
            
            if sub_opcion == "1":
                try:
                    entrada = input("\nIngrese dos numeros primos (p q): ").strip().split()
                    p = int(entrada[0])
                    q = int(entrada[1])
                    
                    generar_claves(p, q)
                    
                except (ValueError, IndexError):
                    print("Error: Formato invalido. Use: p q (ejemplo: 61 53)")
            
            elif sub_opcion == "2":
                # Elegir dos primos diferentes al azar
                primos_seleccionados = random.sample(PRIMOS, 2)
                p = primos_seleccionados[0]
                q = primos_seleccionados[1]
                
                print(f"\nPrimos elegidos al azar: p={p}, q={q}")
                generar_claves(p, q)
            
            else:
                print("Opcion no valida")
        
        elif opcion == "2":
            mensaje = input("\nIngrese el mensaje a encriptar: ").strip()
            
            if mensaje:
                encriptar(mensaje)
            else:
                print("Error: El mensaje no puede estar vacio")
        
        elif opcion == "3":
            try:
                entrada = input("\nIngrese el texto cifrado [num1, num2, ...]: ").strip()
                entrada = entrada.replace('[', '').replace(']', '')
                cifrados = [int(x.strip()) for x in entrada.split(',')]
                
                desencriptar(cifrados)
                
            except ValueError:
                print("Error: Formato invalido. Use: num1, num2, num3")
        
        elif opcion == "4":
            print("\nPrograma finalizado")
            break
        
        else:
            print("Opcion no valida")


if __name__ == "__main__":
    menu()