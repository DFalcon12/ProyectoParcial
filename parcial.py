import Crypto.Util.number
import Crypto.Random
import hashlib

M = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris consectetur sem diam, vitae ultrices nibh finibus non. Sed cursus porta efficitur. Aliquam tempus, felis quis interdum mollis, justo lacus faucibus diam, eget dapibus nibh velit in justo. Phasellus nec ante ultricies, placerat velit vel, interdum sapien. Proin sed euismod neque. In at mattis augue. Nunc vestibulum orci sapien, suscipit dapibus mi placerat a. Nam luctus mauris elit, vitae egestas nibh faucibus nec. Aenean augue est, imperdiet sed urna et, auctor scelerisque nisi. Maecenas congue sem at mattis dignissim. Pellentesque elementum faucibus tristique. Phasellus dapibus mi eu leo commodo posuere. Integer rhoncus ex id pretium consectetur. Ut vel mattis orci.Etiam fermentum ante ut nibh iaculis blandit. Nunc viverra a ex ut maximus. Maecenas faucibus libero felis, ultrices iaculis nunc hendrerit ut. Praesent vitae diam congue, porta ante feugiat, condimentum justo. Nam aliquam diam vel orci congue tincidunt id ut orci. Duis in turpis quis augue lacinia vestibulum"


hashed_msg = hashlib.sha256(M.encode('utf-8')).hexdigest()
M_bytes = M.encode('utf-8')

# Calcular el hash SHA-256 del mensaje
hash_sha256 = hashlib.sha256(M_bytes).hexdigest()
print("SHA-256 Hash:", hash_sha256)

msg_div = [M[i:i+128] for i in range (0, len(M), 128)]
print(len(msg_div))
print(msg_div)

bits = 1024

pA = Crypto.Util.number.getPrime(bits, randfunc = Crypto.Random.get_random_bytes)
print("Este es el primo de Alice", pA ,"\n")
qA = Crypto.Util.number.getPrime(bits, randfunc = Crypto.Random.get_random_bytes)
print("qA", pA ,"\n")
pB = Crypto.Util.number.getPrime(bits, randfunc = Crypto.Random.get_random_bytes)
print("Este es el primo de Bob", pA ,"\n")
qB = Crypto.Util.number.getPrime(bits, randfunc = Crypto.Random.get_random_bytes)
print("qB", pA ,"\n")

#Llave publica
nA = pA * qA
print("nA", nA, "\n")
nB = pB * qB
print("nB", nB, "\n")

#Calcular el indicador de Euler Phi
phiA = ((pA - 1) * (qA - 1))
print("phiA", phiA, "\n")
phiB = ((pB - 1) * (qB - 1))
print("phiB", phiB, "\n")

#Numero de fermat
e = 65537
#Calcular las llave privadas
dA = Crypto.Util.number.inverse(e, phiA)
print("dA", dA , "\n")

dB = Crypto.Util.number.inverse(e, phiB)
print("dB", dB , "\n")

msgs_encrypted = []
#Cifrar los mensajes
for j in msg_div:   
    m = int.from_bytes(str(j).encode('utf-8'), byteorder='big')
    #print("mensaje convertido en entero: ", m ,"\n")
    #print(m , "\n")
    c = pow(m,e,nB)
    print("Mensaje cifrado: ", c, "\n")
    msgs_encrypted.append(c)

msgs_dc = []
for i in msgs_encrypted:
    des = pow(i, dB, nB)
    #print ("Mensaje descifrado: ", des, "\n")
    #Convertir el mensaje a texto
    #msg_final = int.to_bytes(des, len(M), byteorder = 'big').decode('utf-8')
    msg_final = des.to_bytes((des.bit_length() + 7) // 8, byteorder='big').decode('utf-8')
    print("Mensaje final: ", msg_final, "\n")
    msgs_dc.append(msg_final)

print(msgs_dc)

decrypted_msgs = []

joined_msg = "".join(decrypted_msgs)

print("Mensaje descifrado y unido: ", joined_msg)

if M == joined_msg:
    print("Los mensajes son iguales")
else:
    print("Los mensajes no son iguales")

