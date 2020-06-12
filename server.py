import socket
import sys, thread
import hashlib, select
from Crypto.Cipher import AES
import mysql.connector
import base64, os
host = ""
port = 5000
from Crypto import Random
from Crypto.PublicKey import RSA

os.popen('service mysql start')

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


def key_hash(password):
	key = hashlib.sha512(password.strip()).hexdigest()
	key = hashlib.md5(key.strip()).hexdigest()
	return key

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
	'''for x in decoded:
		if x not in "qwertyuiop[\]asdfghjkl;'zxcvbnm,./QWERTYU?!@#$%(*&^%IOPASDFGHJKLZXCVBNM,./;'""'1234567890-=+":
			return None
		else:'''
	return decoded

buf = 4096

#send
			#print data
#while True:
#	(data, address) = s.recvfrom(buf)
#	data = decrypt(key, data)
#	if data == None:
#		pass
#	else:
#		sendall(data)
#	if address not in user:
#		user.append(address)
#		s.sendto(" ", address)
	#print data, address
	#print user

onusers = []
user_key = {}

privatekey, publickey = generate_keys()

if len(sys.argv) == 3:
	host = sys.argv[1]
	#key = sys.argv[2]
#	key = key_hash(key_hash(key))
	port = int(sys.argv[2])
else:
	print "Usage python server.py <ip_address> <port>"
	exit()


def sendall(data, s, sock):
	for socks in socket_list:
		if socks != sock and socks != s:
			try:
				#print data
				key = RSA.importKey(user_key[socks])
				socks.send(encrypt_message(data, key))
			except:
				socks.close()
				if socks in socket_list:
					socket_list.remove(socks)
			try:
				key.exportKey()
			except:
				pass


def auth(sock, addr, con, server_socket):
	global user_key
	global uname
	sock.send(publickey.exportKey())
	his_pub = sock.recv(buf)
	username = str(sock.recv(buf)).strip()
	password = str(sock.recv(buf)).strip()
	sql_query = "select * from data where username = '%s';"%(username)
	#print sql_query
	try:
		cur = con.cursor()
		cur.execute(sql_query)
	except:
		pass
	back = cur.fetchall()
	print back , username
	if back:
		for uname, passwd in back:
			if username == uname:
				if username in onusers:
					sock.send(encrypt_message("Logged", RSA.importKey(his_pub)))

				elif password == passwd:
					sendall('\033[91m%s Joined\033[0m\n'%username, server_socket, sock)
					sock.send(encrypt_message('Confirmed',  RSA.importKey(his_pub)))
					socket_list.append(sock)
					user_key[sock] = his_pub
					users[sock] = username
					onusers.append(username)

				else:
					print uname
					print "wrong"
					sock.send(encrypt_message('Wrong',  RSA.importKey(his_pub)))
	else:
		sock.send(encrypt_message('user not found',  RSA.importKey(his_pub)))
		res = sock.recv(buf)
		print res
		if "~new_user~" in res:
			sock.send(new_user(res.split("|")[1], res.split("|")[2], con))

users = {}
socket_list = []

def new_user(username, password, con):
	seql = "select * from data where username = '%s';"%(username)
	try:
		cur = con.cursor()
		cur.execute(seql)
		back = cur.fetchall()
		if back:
			return "Used"
	except:
		return False
	seql = "insert into data (username, password) values ('%s', '%s');"%(username, password)
	try:
		cur = con.cursor()
		cur.execute(seql)
		con.commit()
		print "done"
		return "done"
	except:
		print "failed"
		return "failed"


def server():
	con = mysql.connector.connect(host='', user='', password='', database='')
	server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	server_socket.bind((host, port))
	server_socket.listen(10)
	socket_list.append(server_socket)
	#print privatekey.exportKey()
	print 'Server Started Port %d'%port

	while True:
		read, write, error = select.select(socket_list, [], [], 0)
		for socks in read:
			if socks == server_socket:
				sock, addr = server_socket.accept()
				thread.start_new_thread(auth, (sock, addr, con, server_socket,))

			else:
				try:
					data = socks.recv(buf)
					if data:
						data = decrypt_message(data, privatekey)
						if data == '!online_users\n':

							z = ''
							for x in onusers:
								z += str(x)+','
							socks.send(z)
						else:
							sendall(data, server_socket, socks)
					else:
						sendall('\033[91m'+ users[socks] +' Is Offline Now'+'\n\033[0m', server_socket, socks)
						if users[socks] in onusers:
							onusers.remove(users[socks])
						if socks in socket_list:
							socket_list.remove(socks)
				except:
					if not data:
						sendall('\r '+users[socks] +' Is Offline Now', server_socket, socks)
						if users[socks] in onusers:
							onusers.remove(users[socks])
server()
