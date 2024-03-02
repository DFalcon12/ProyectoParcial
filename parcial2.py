import Crypto.Util.number
import Crypto.Random
import hashlib
import io 
import PyPDF2
from PyPDF2 import PdfReader
#from PymuPDF import Document, PDF_Sign

bits = 1024

#Obtener primos para A y B

pA = Crypto.Util.number.getPrime(bits, randfunc = Crypto.Random.get_random_bytes)
print("Este es el primo de Alice", pA ,"\n")
qA = Crypto.Util.number.getPrime(bits, randfunc = Crypto.Random.get_random_bytes)
print("qA", pA ,"\n")
pB = Crypto.Util.number.getPrime(bits, randfunc = Crypto.Random.get_random_bytes)
print("Este es el primo de Bob", pA ,"\n")
qB = Crypto.Util.number.getPrime(bits, randfunc = Crypto.Random.get_random_bytes)
print("qB", pA ,"\n")
pC = Crypto.Util.number.getPrime(bits, randfunc = Crypto.Random.get_random_bytes)
print("Este es el numero primo de la AutoridadC", pC ,"\n")
qC = Crypto.Util.number.getPrime(bits, randfunc = Crypto.Random.get_random_bytes)
print("qC", qC ,"\n")
#Llave publica
nA = pA * qA
print("nA", nA, "\n")
nB = pB * qB
print("nB", nB, "\n")
nC = pC * qC
print("nC", nC, "\n")

#Calcular el indicador de Euler Phi

phiA = ((pA - 1) * (qA - 1))
print("phiA", phiA, "\n")
phiB = ((pB - 1) * (qB - 1))
print("phiB", phiB, "\n")
phiC = ((pC - 1) * (qC - 1))
print("phiC", phiC, "\n")

#Numero de fermat
e = 65537
#Calcular las llave privadas
dA = Crypto.Util.number.inverse(e, phiA)
print("dA", dA , "\n")

dB = Crypto.Util.number.inverse(e, phiB)
print("dB", dB , "\n")

dC = Crypto.Util.number.inverse(e, phiC)
print("dC", dC , "\n")

def sign_document(document, private_key):
    hash_document = hashlib.sha256(document).digest()
    signature = pow(int.from_bytes(hash_document, byteorder='big'), private_key[0], private_key[1])
    return signature
def verify_signature(document, signature, public_key):
    hash_document = hashlib.sha256(document).digest()
    hash_signature = pow(signature, public_key[0], public_key[1])
    return hash_document == hash_signature.to_bytes((hash_signature.bit_length() + 7) // 8, byteorder='big')

with open('NDA.pdf', 'rb') as file:
    document = file.read()

#ALice firma el documento
A_signature = sign_document(document, (dA, nA))

#Alice modifica el PDF
with open('Alice_signed_NDA.pdf', 'wb') as file:
    writer = PyPDF2.PdfWriter()
    reader = PyPDF2.PdfReader(io.BytesIO(document))
    for page_num in range(len(reader.pages)):
        writer.add_page(reader.pages[page_num])
    writer.add_metadata({'/Firma_Alice': str(A_signature)})
    writer.write(file)

#La AutoridadC obtiene el PDF y lo comprueba 
alice_public_key = (e, nA)
valid_signature = verify_signature(document, A_signature, alice_public_key)
if valid_signature:
    print("La AutoridadC verifico la firma de Alice")
else:
    print("La AutoridadC no verifico la firma de Alice")

#La autoridad firma el pdf
ac_signature = sign_document(document, (dC, nC))

with open('AC_signed_NDA.pdf', 'wb') as file:
    writer = PyPDF2.PdfWriter()
    reader = PyPDF2.PdfReader(io.BytesIO(document))

    for page_num in range(len(reader.pages)):
        writer.add_page(reader.pages[page_num])

    writer.add_metadata({'/Firma_AC': str(ac_signature)})  
    writer.write(file)

#Bob recibe el PDF y lo comprueba con la llave publica de la AutoridadC
ac_public_key = (e, nC)
valid_signature = verify_signature(document, ac_signature, ac_public_key)
if valid_signature:
    print("Bob verifico la firma de la autoridad")
else:
    print("Bob no verifico la firma de la autoridad")


