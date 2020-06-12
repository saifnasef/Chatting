from socket import *
from Crypto.Cipher import AES
import base64, select
import random, getpass, time, socket, os, thread, threading, hashlib, sys
from collections import OrderedDict
from Crypto import Random
from Crypto.PublicKey import RSA


def generate_keys():
	# RSA modulus length must be a multiple of 256 and >= 1024
	modulus_length = 256*4 # use larger value in production
	privatekey = RSA.generate(modulus_length, Random.new().read)
	publickey = privatekey.publickey()
	return privatekey, publickey

def encrypt_message(a_message , publickey):
	encrypted_msg = publickey.encrypt(a_message, 32)[0]
	encoded_encrypted_msg = base64.b64encode(encrypted_msg) # base64 encoded strings are database friendly
	return encoded_encrypted_msg

def decrypt_message(encoded_encrypted_msg, privatekey):
	decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)
	decoded_decrypted_msg = privatekey.decrypt(decoded_encrypted_msg)
	return decoded_decrypted_msg
buf = 4096

#hash
def key_hash(password):
	key = hashlib.sha512(password.strip()).hexdigest()
	key = hashlib.md5(key.strip()).hexdigest()
	return key

#define new function to recseive messages


def encrypt(secret,data):
	BLOCK_SIZE = 32
	PADDING = 'q'
	pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
	EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
	cipher = AES.new(secret)
	encoded = EncodeAES(cipher, data)
	return encoded

def decrypt(secret,data):
	BLOCK_SIZE = 32
	PADDING = 'q'
	pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
	DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
	cipher = AES.new(secret)
	decoded = DecodeAES(cipher, data)
	return decoded


#The main function used to send data to the server
# def send(s):
# 	global data
# 	s.bind(addr)
# 	s.connect(server)
# 	welcome = encrypt(key, name+" Joined The Chat")
# 	s.send(welcome)
# 	os.popen('reset')
# 	print "\033[1m[+]Connected To The Server\n"
# 	while True:
# 		data = raw_input("\033[34m["+name+"]: ")
# 		data = "[" +name+"]: "+data
# 		data = encrypt(key,data)
# 		s.send(data)
# def recv(w):
# 	global data
# 	thread.start_new_thread(send, (s,))
# 	while True:
# 		income, ar = w.recvfrom(buf)
# 		incomee = decrypt(key,income)
# 		print ("\n\033[91m%s"%incomee)
# 		sys.stdout.write("\033[34m["+name+"]: " ); sys.stdout.flush()
#recv(s)


def new_user(sock):
	x = True
	while x:
		username = raw_input("Enter Your Username: ")
		if "'" in username or '"' in username or "\\" in username or "/" in username:
			print "Choose another username"
		else:
			x = False
	while True:
		password = raw_input("Enter Your Password: ")
		if raw_input("Enter Your Password Again: ") == password:
			new = "~new_user~|"+username+"|"+key_hash(password.strip())

			try:
				sock.send(new)
				response = sock.recv(buf)
				if response == "done":
					print("User Created Please Log In Again")
					exit()
				elif response == "Used":
					print "Username Is Used, try a different one."
					exit()

			except:
				exit("Failed :(")

privatekey, publickey = generate_keys()
def chat():

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(2)

	if(len(sys.argv) < 3) :
		print 'Usage : python send.py <hostname> <port>'
		sys.exit()
	server_ip = sys.argv[1]
	server_port = int(sys.argv[2])
	server = (server_ip, server_port)

	#key = key_hash(key_hash(sys.argv[4]))

	try:
		s.connect((server_ip, server_port))
	except:
		sys.stdout.write('\033[91m'+'Unable To Connect\n'+'\033[0m')
		exit()
	print "\033[34mConnected To Server\033[0m"+"\n"
	server_public = s.recv(buf)
	server_public = RSA.importKey(server_public)
	#print server_public
	s.send(publickey.exportKey())
	uname = raw_input('\033[1mUsername: ')
	password = raw_input('Password: \033[0m')
	try:
		password =  key_hash(password.strip())
		s.send(uname)
		s.send(password)
		response = s.recv(buf)
		response = decrypt_message(response, privatekey)
		if response == 'Confirmed':
			os.popen('reset')
			print "\033[34mAuthenticated To The Server\033[0m"+"\n"
				#print publickey.exportKey()
				#print privatekey.exportKey()
			sys.stdout.write("\033[34m"+'['+uname+"]:\033[0m"); sys.stdout.flush()
		elif response == "Logged":
			print "\033[91mAlready Logged In\033[0m"
			exit()

		elif response == 'Wrong':
			print '\033[91mIncorrect Password\033[0m'
			exit()
		else:
			print '\033[91mUsername Not Found\033[0m'
			ask = raw_input("Do You want to create a new user? Y/N : ")
			if ask.lower() == 'y':
				new_user(s)
			else:
				exit()

	except:
		exit()

   	while True:
		socket_list = [sys.stdin, s]
		read_socket, write_socket, error_socket = select.select(socket_list, [], [])
		for sock in read_socket:
			if sock == s:
				data = s.recv(buf)
				if not data or data.strip() == '':
					sys.stdout.write('\033[91m'+'Disconnected From Server\n'+'\033[0m')
					print data
					exit()
				data = decrypt_message(data, privatekey)
				if not data:
					pass
					sys.stdout.write('\033[91m'+'Disconnected From Server\n'+'\033[0m')
					exit()
				else:
					sys.stdout.write('\n\033[1m'+data+'\033[0m')
					sys.stdout.write("\033[34m"+'['+uname+"]: \033[0m"); sys.stdout.flush()
			else:
				msg = sys.stdin.readline()
				if msg == '!online_users\n':
					msg = encrypt_message(msg, server_public)
					s.send(msg)
					users = s.recv(buf)
					print "\033[1mOnline Users"
					for i in users.split(','):
						if i:
							print i
					sys.stdout.write("\033[0m\033[34m"+'['+uname+"]: \033[0m"); sys.stdout.flush()
				else:
					if msg.strip():
						msg = "["+uname+"]: " + msg
						msg = encrypt_message(msg, server_public)
						s.send(msg)
						sys.stdout.write("\033[34m"+'['+uname+"]: \033[0m"); sys.stdout.flush()
					else:
						sys.stdout.write("\033[34m"+'['+uname+"]: \033[0m"); sys.stdout.flush()

chat()
