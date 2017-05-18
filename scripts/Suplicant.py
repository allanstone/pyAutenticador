import hashlib

class Suplicant(object):
	"""Clase Suplicant"""
	def __init__(self, user,passwd,usersFile,requestFile):
		self.user=user
		self.passwd=passwd
		self.usersFile=usersFile
		self.requestFile=requestFile


	def signIn(self):
		"""Método para registrar username"""
		with open(self.usersFile,'w') as f:
			f.write(self.user+"|"+Suplicant.sha256(self.passwd))

	def sendCredentials(self):
		with open(self.usersFile,'w') as f:
			f.write(self.user+"|"+Suplicant.sha256(self.passwd))


	@classmethod
	def sha256(cls,msg):
		"""Método de clase para generar el hash de una caden en SHA256"""
		return hashlib.sha256(msg.encode('utf-8')).hexdigest()

if __name__ == '__main__':
	sup=Suplicant("alan","gato123","users.txt","requestUsers.txt")
	sup.signIn()
	#Inicia autenticación por derivación
	sup.sendCredentials()





		
		