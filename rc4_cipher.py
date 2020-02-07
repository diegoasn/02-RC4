#RC4 Cipher
import fileinput

"""Función cast_bytes(text)
	Convierte una cadena de caracteres a una lista de bytes.
   	text - Cadena de caracteres a convertir"""
def cast_bytes(text):
	text = text.encode('utf-8')
	bytes_list = list(text)
	return bytes_list

"""Función list_to_cipher_msg(cipher)
	Convierte la lista de bytes correspondiente al mensaje cifrado en una sucesión de números hexadecimales.
   	cipher - Lista de bytes 'cifrados'"""
def list_to_cipher_msg(cipher):
	for i in range(len(cipher)):
		cipher[i] = str(hex(cipher[i])[2:]).upper()
		if len(cipher[i]) == 1:
			cipher[i] = '0' + cipher[i]
	c_msg = ''.join(cipher)
	return c_msg

"""Función ksa(key)
	Key Schedculing Algorithm, inicializa el arreglo S y lo permuta respecto a la llave.
   	key - Llave de cifrado"""
def ksa(key):
	s, j = [x for x in range(256)], 0
	for i in range(256):
		j = (j + s[i] + key[i % len(key)]) % 256
		s[i], s[j] = s[j], s[i]
	return s

"""Función prga(s, msg_len)
	Pseudo-random generation algorithm, genera el 'key stream' para el cifrado del mensaje.
   	s - Arreglo proveniente de KSA
	msg_len - tamaño en bytes del mensaje a cifrar"""
def prga(s, msg_len):
	i, j, pseudo_random = 0, 0, list()
	while len(pseudo_random) < msg_len:
		i = (i + 1) % 256
		j = (j + s[i]) % 256
		s[i], s[j] = s[j], s[i]
		k = s[(s[i] + s[j]) % 256]
		pseudo_random.append(k)
	return pseudo_random

"""Función rc4(key, msg)
	Realiza la operación XOR entre el mensaje a cifrar y su respectivo key stream, devuelve el mensaje cifrado en formato hexadecimal.
   	key - Llave de cifrado
	msg - Mensaje a cifrar"""
def rc4(key, msg):
	key, msg, cipher = cast_bytes(key), cast_bytes(msg), list()
	s = ksa(key)
	pseudo_random = prga(s, len(msg))
	for i in range(len(msg)):
		cipher.append(msg[i] ^ pseudo_random[i])
	c_msg = list_to_cipher_msg(cipher)
	return c_msg

lines = list()
for line in fileinput.input():
	line = line.replace('\n', '')
	lines.append(line)

print(rc4(lines[0], lines[1]))
