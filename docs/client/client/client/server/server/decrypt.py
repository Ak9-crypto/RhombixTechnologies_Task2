import requests, base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

SERVER = 'http://127.0.0.1:5000'

def load_privkey(path):
    with open(path,'rb') as f:
        return RSA.import_key(f.read())

def download_and_decrypt(file_id, privkey_path, user_id):
    headers = {'X-User': user_id}
    meta = requests.get(f'{SERVER}/download/{file_id}', headers=headers).json()
    blob = requests.get(SERVER + meta['download_url'], headers=headers).content

    priv = load_privkey(privkey_path)
    cipher_rsa = PKCS1_OAEP.new(priv)
    aes_key = cipher_rsa.decrypt(base64.b64decode(meta['encrypted_key']))

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=base64.b64decode(meta['nonce']))
    plaintext = cipher.decrypt_and_verify(blob, base64.b64decode(meta['tag']))

    with open('downloaded_' + meta['filename'], 'wb') as f:
        f.write(plaintext)
    print('Decrypted and saved as downloaded_' + meta['filename'])

if __name__ == '__main__':
    download_and_decrypt('YOUR_FILE_ID', 'recipient_priv.pem', 'userB')
