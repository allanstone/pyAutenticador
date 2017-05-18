import hashlib
import socket
import sys

class Suplicant(object):
	"""Clase Suplicant"""
	def __init__(self, user,passwd,usersFile,ip,port):
		self.user=user
		self.passwd=passwd
		self.usersFile=usersFile
		self.ip=ip
		self.port=port


	def signIn(self):
		"""Método para registrar username"""
		with open(self.usersFile,'w') as f:
			f.write(self.user+"|"+Suplicant.sha256(self.passwd))

	def openConnection(self):
		sock=None
		try:
			sock=socket.socket()
			sock.connect((self.ip,self.port))
			print("Suplicante en "+socket.gethostname()+" conexión exitosa.")  
		except socket.error as se:
			print("Imposible conectar con el Autenticador\n Motivo: %s\n Finalizando ejecución..." % se)
			sys.exit(1)
		finally:
			return sock

	def sendCredentials(self):
		s=self.openConnection()
		if s:
			print("No se ha establecido conexión con el Autenticador")
		else:
			s.send(self.user+"|"+Suplicant.sha256(self.passwd))

	@classmethod
	def sha256(cls,msg):
		"""Método de clase para generar el hash de una caden en SHA256"""
		return hashlib.sha256(msg.encode('utf-8')).hexdigest()

if __name__ == '__main__':
	sup=Suplicant("alan","gato123","users.txt","localhost","666")
	sup.signIn()
	#Inicia autenticación por derivación
	sup.sendCredentials()





		
		