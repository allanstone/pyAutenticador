import sys
import hmac
from random import randint
from hashlib import sha256
from CipherAES import encrypt,decrypt

class Authenticator(object):
	"""Clase Authenticator"""
	def __init__(self,usersFile,authFile,requestFile):
		self.usersFile=usersFile		
		self.authFile=authFile
		self.requestFile=requestFile		
		self.k1="Diffie"
		self.k2="Hellman"
		
	def readData(self):
		with open(self.usersFile,'r') as f:
			return f.read().split("|")

	def registerSup(self,supData,hmacMethod="rfc"):
		with open(self.authFile,'a') as f:
			if hmacMethod="rfc":
				x=supData[0]+"|"+str(self.hmacRFC(supData[0],supData[1],Authenticator.makeNonce(),self.k1,self.k2))+"\n"
			else:
				x=supData[0]+"|"+self.hmacBuiltIn("",supData[0]+supData[1])+"\n"
			f.write(x)
			return x
			
	def authenticateSup(self):
		with open(self.usersFile,'r') as uF, open(self.requestFile,'r+') as rF:
			users=uF.readlines()
			supData=rF.read()
			#requestFile.seek(0)
			#requestFile.truncate()
		for user in users:
			if user==supData:
				return supData
		return False

	def sendHmac(self,supData,x):
		with open(supData[0]+".txt","w") as f:
			f.write("".join(supData)+"|"+x)


	def hmacBuiltIn(self,key,msg):
		"""Método usando el módulo de hmac"""
		if key=="":
			key=Authenticator.makeNonce()
		key=self.k1+self.k2+key
		return hmac.new(key.encode('utf-8'),msg.encode('utf-8'),sha256).hexdigest()

	def hmacRFC(self,user,hashedPass,nonce,k1,k2,blocksize=32):
		"""Método que genera el código mac usando el RFC 2014"""
		if len(k1) > blocksize:
			k1=sha256(k1).digest()
		k1=k1.encode('utf-8')+bytearray(blocksize-len(k1))
		if len(k2) > blocksize:
			k2=sha256(key).digest()
		k2=k2.encode('utf-8')+bytearray(blocksize-len(k2))
		#print("Longitud de k1: ",len(k1))
		#print("Longitud de k2: ",len(k2))
		return encrypt(sha256(k1+encrypt(k2,user+hashedPass)).hexdigest(),nonce)
		
	@classmethod
	def makeNonce(cls):
		"""Métoo de clase para generar un número pseudoaleatorio."""
		return str(randint(0, 100000000))

if __name__ == '__main__':
	aut=Authenticator("users.txt","authenticatedUsers.txt","requestUsers.txt")
	#2
	supCredentials=aut.readData()
	#3
	x=aut.registerSup(supCredentials)
	aut.sendHmac(supData,x)
	#Inicia autenticacion por derivacion
	#4
	supData=aut.authenticateSup()
	if(supData):
		print("Usuario Auntenticado: ",supData.split("|")[0])
	else:
		print("Usuario desconocido, finalizando proceso")
		sys.exit()
	#5
	