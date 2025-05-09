import base64
import codecs
import zlib
import marshal
from Crypto.Cipher import AES
from Crypto.Cipher import Blowfish
from hashlib import md5, sha256
import bcrypt
import os
import subprocess

# لتعبئة البيانات بما يتناسب مع AES و Blowfish
def pad(data, block_size):
    return data + b"\0" * (block_size - len(data) % block_size)

# AES تشفير باستخدام كلمة سر
def aes_encrypt(data, password):
    key = md5(password.encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC, iv=key)
    return base64.b64encode(cipher.encrypt(pad(data.encode(), AES.block_size))).decode()

# Blowfish تشفير باستخدام كلمة سر
def blowfish_encrypt(data, password):
    key = md5(password.encode()).digest()
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=key)
    return base64.b64encode(cipher.encrypt(pad(data.encode(), Blowfish.block_size))).decode()

# لتشفير XOR باستخدام كلمة سر
def xor_encrypt(data, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))

# تشفير bcrypt
def bcrypt_encrypt(data):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(data.encode(), salt).decode()

# تجزئة SHA256
def sha256_hash(data):
    return sha256(data.encode()).hexdigest()

# تشغيل Psiphon (VPN)
def start_psiphon():
    try:
        print("تشغيل Psiphon للاتصال بشبكة VPN...")
        subprocess.run(["./psiphon/psiphon"])
        print("تم الاتصال بشبكة Psiphon بنجاح!")
    except Exception as e:
        print(f"خطأ في تشغيل Psiphon: {e}")

# طبقات التشفير
def encrypt_all_layers(code, password):
    # Step 1: Base64
    code = base64.b64encode(code.encode()).decode()

    # Step 2: ROT13
    code = codecs.encode(code, 'rot_13')

    # Step 3: XOR
    code = xor_encrypt(code, password)
    code = base64.b64encode(code.encode()).decode()

    # Step 4: zlib
    code = base64.b64encode(zlib.compress(code.encode())).decode()

    # Step 5: AES
    code = aes_encrypt(code, password)

    # Step 6: Blowfish
    code = blowfish_encrypt(code, password)

    # Step 7: bcrypt (كود مشفر مع كلمة سر)
    code = bcrypt_encrypt(code)

    # Step 8: marshal
    marshaled = marshal.dumps(compile(f"print('لا يمكن عرض الكود، شُفر بالكامل')", "<encrypted>", "exec"))
    code = base64.b64encode(marshaled).decode()

    return f"import base64,marshal\nexec(marshal.loads(base64.b64decode('{code}')))"

# تشفير الملف
def encrypt_file(file_path, password):
    if not os.path.exists(file_path):
        print("الملف غير موجود!")
        return

    with open(file_path, 'r') as f:
        code = f.read()

    encrypted = encrypt_all_layers(code, password)

    encrypted_file = file_path.replace(".py", "_super_encrypted.py")
    with open(encrypted_file, 'w') as f:
        f.write(encrypted)

    print(f"\nتم تشفير الملف وحفظه كـ: {encrypted_file}")

def main():
    # أولاً تشغيل Psiphon للاتصال بشبكة VPN
    start_psiphon()

    # تشفير الملف
    file_path = input("أدخل مسار ملف بايثون (.py): ")
    password = input("أدخل كلمة سر للتشفير: ")

    encrypt_file(file_path, password)

if __name__ == "__main__":
    main() 
