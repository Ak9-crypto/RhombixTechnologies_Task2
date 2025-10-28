import os, requests, base64, hashlib
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

SERVER = 'http://127.0.0.1:5000'

def load_recipient_pubkey(path):
    with open(path,'rb') as f:
        return RSA.import_key(f.read())

def encrypt_file_and_upload(local_path, recipient_pubkey_path, recipient_id, owner_id):
    pub = load_recipient_pubkey(recipient_pubkey_path)
    aes_key = get_random_bytes(32)
    data = open(local_path,'rb').read()
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    nonce = cipher.nonce

    cipher_rsa = PKCS1_OAEP.new(pub)
    enc_key = cipher_rsa.encrypt(aes_key)
    sha256 = hashlib.sha256(ciphertext).hexdigest()

    files = {'ciphertext': ('blob', ciphertext)}
    data = {
        'recipient_id': recipient_id,
        'filename': os.path.basename(local_path),
        'encrypted_key': base64.b64encode(enc_key).decode(),
        'nonce': base64.b64encode(nonce).decode(),
        'tag': base64.b64encode(tag).decode(),
        'sha256': sha256
    }
    headers = {'X-User': owner_id}
    r = requests.post(SERVER+'/upload', files=files, data=data, headers=headers)
    print('Upload Response:', r.status_code, r.text)

if __name__ == '__main__':
    encrypt_file_and_upload('secret.pdf', 'recipient_pub.pem', 'userB', 'userA')
