import hmac
from hashlib import sha256, md5
from random import randint
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

	def registerSup(self,supData):
		with open(self.authFile,'a') as f:
			#f.write(supData[0]+"|"+str(self.hmacRFC(supData[0],supData[1],Authenticator.makeNonce(),self.k1,self.k2))+"\n")
			f.write(supData[0]+"|"+self.hmacBuiltIn("",supData[0]+supData[1])+"\n")
			
	def authenticateSup(self):
		with open(self.usersFile,'r') as uF, open(self.requestFile,'r') as rF:
			return f.read().split("|")
	
	def hmacBuiltIn(self,key,msg):
		"""Método usando el módulo de hmac"""
		if key=="":
			key=Authenticator.makeNonce()
		key=self.k1+self.k2+key
		return hmac.new(key.encode('utf-8'),msg.encode('utf-8'),sha256).hexdigest()

	def hmacRFC(self,user,hashedPass,nonce,k1,k2,blocksize=32):
		"""Método que genera el código mac usando el RFC 2014"""
		if len(k1) > blocksize:
			k1 = md5(k1).digest()
		k1=k1.encode('utf-8')+bytearray(blocksize-len(k1))
		if len(k2) > blocksize:
			k2=md5(key).digest()
		k2=k2.encode('utf-8')+bytearray(blocksize-len(k2))
		#print("Longitud de k1: ",len(k1))
		#print("Longitud de k2: ",len(k2))
		return encrypt(md5(k1+encrypt(k2,user+hashedPass)).hexdigest(),nonce)
		

	@classmethod
	def makeNonce(cls):
		"""Métoo de clase para generar un número pseudoaleatorio."""
		return str(randint(0, 100000000))

if __name__ == '__main__':
	aut=Authenticator("users.txt","authenticatedUsers.txt","requestUsers.txt")
	supCredentials=aut.readData()
	aut.registerSup(supCredentials)
	#Inicia autenticacion por derivacion

