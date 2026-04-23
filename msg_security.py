import re
import des
import rsa
import sha1
import database_helper


#DES (for chat encrption)------------------------------------------------------------------------------------------------------------------- 

def set_des_key():
    key_des = database_helper.get_des_key()
    return  key_des

def decrypt_message(msg):
   key_des=set_des_key()
   decrypted_msg=des.des_decrypt_message(msg,key_des)
   return decrypted_msg

def encrypt_message(msg):
   key_des=set_des_key()
   encrypted_msg=des.des_encrypt_message(msg, key_des)
   return encrypted_msg

def Decrypt_keys(Encrypted_key): # function to slice string from (a,b) format to a and b. returns a list of integers
    keystring=decrypt_message(Encrypted_key)
    match = re.match(r'\((\d+),\s*(\d+)\)', keystring)
    if match:
        part1 = int(match.group(1))
        part2 = int(match.group(2))
        key_pair=[part1,part2]
        return key_pair
    else:
        raise ValueError("String format is incorrect")
     
#Sha1 (for msg validation and password storing) ------------------------------------------------------------------------------------------------------------------- 

def hash_data(Plain_Text):
    hashed_data = sha1.calculate_sha1(Plain_Text)
    return hashed_data
 
def update_password(account_id,new_password):
   password_hash=hash_data(new_password)
   database_helper.update_password(account_id, password_hash)
   
    

#RSA (for msgs sent over sockets) ------------------------------------------------------------------------------------------------------------------- 

     
def RSA_encrypt(plaintext,reciever_ip_address):
   public_key=database_helper.get_public_key(reciever_ip_address)
   public_key=Decrypt_keys(public_key) # originally encrypted with DES
   encrypted_msg=rsa.encrypt(public_key, plaintext)
   return encrypted_msg

def RSA_decrypt(cipher_text,Account_id):
   Private_key=database_helper.get_private_key(Account_id)
   Private_key=Decrypt_keys(Private_key) # originally encrypted with DES
   decrypted_msg=rsa.decrypt(Private_key, cipher_text)
   return decrypted_msg

