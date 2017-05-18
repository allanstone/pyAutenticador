import hmac
from hashlib import sha256
from random import randint
from cifrado import encrypt,decrypt

class Authenticator(object):
	"""Clase Authenticator"""
	def __init__(self,usersFile,authFile):
		self.usersFile=usersFile		
		self.authFile=authFile		
		self.k1="Diffie"
		self.k2="Hellman"
		
	def readData(self):
		with open(self.usersFile,'r') as f:
			return f.read().split("|")

	def registerSup(self,supData):
		with open(self.authFile,'a') as f:
			f.write(supData[0]+"|"+str(self.hmacSHA265(supData[0],supData[1],Authenticator.makeNonce(),self.k1,self.k2)))
			#f.write(supData[0]+"|"+self.hmacBuiltIn("",supData[0]+supData[1]))
			
	def authenticateSup(self):
		pass

	def hmacBuiltIn(self,key,msg):
		"""Método usando el módulo de hmac"""
		if key=="":
			key=Authenticator.makeNonce()
		key=self.k1+self.k2+key
		return hmac.new(key.encode('utf-8'),msg.encode('utf-8'),sha256).hexdigest()

	def hmacRFC(self,user,hashedPass,nonce,k1,k2):
		"""Método que genera el código mac usando el RFC 2014"""

		return encrypt(md5(k1 + encrypt(k2 , user+hashedPass)).hexdigest(),nonce)
		

	@classmethod
	def makeNonce(cls):
		"""Métoo de clase para generar un número pseudoaleatorio."""
		return str(random.randint(0, 100000000))

if __name__ == '__main__':
	aut=Authenticator("users.txt")
	supCredentials=aut.readData()
	aut.registerSup(supCredentials)
	#Inicia autenticacion por derivacion
