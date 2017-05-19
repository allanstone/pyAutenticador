# Autenticador por dos factores 

Proyecto Final de la materia de Criptografía de la Facultad de Ingeniería UNAM
usando como hash SHA-256 y algoritmo de cifrado simétrico Rijndael.

## SCRIPTS
* Para correr el Autenticador desde linea de comandos se puede realizar de la siguiente forma:

    ```
    $ python Authenticator.py
    ```

* Para correr el Suplicante desde linea de comandos se puede realizar de la siguiente forma:

    ```
    $ python Suplicant.py
    ```
* Para probar los códigos es necesario el modulo **pycrypto** instalado, se puede
     instalar de manera sencilla con la siguiente línea:

    ```
    $ pip install pycrypto
    ```
* O buscar el instalador de esta [lista](http://www.voidspace.org.uk/python/modules.shtml#pycrypto),(Nota: solo para Python 2.6, 2.7 y 3.3)

* Instalación para Python 3.5 mediante [wheels](https://github.com/sfbahr/PyCrypto-Wheels)

* **NOTA:** Asegurarse de tener los [compiladores](http://www.microsoft.com/en-us/download/details.aspx?id=44266) para C++ si se ejecuta en Windows 

* **NOTA:** Pycrypto aún no es compatible con la versión más actual de python (3.6.1)