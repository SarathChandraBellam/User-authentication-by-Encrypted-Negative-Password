import os
import binascii
import json
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
import random
import sqlite3
from sqlite3 import Error
from flask import Flask
from flask import request
from flask import jsonify
import traceback

app = Flask(__name__)
# Configuring the port


class ENP:
    """
    """
    def __init__(self):
        self.BLOCK_SIZE = 16
        self.pad = lambda s: s + (self.BLOCK_SIZE - len(s) % self.BLOCK_SIZE) * chr(self.BLOCK_SIZE - len(s) % self.BLOCK_SIZE)
        self.unpad = lambda s: s[:-ord(s[len(s) - 1:])]
        self.symbols = {"00": "0", "01": "1", "11": "*", "10": "*"}
        self.ndb_val = ""
        self.enp = ""
        self.hex = ""
        self.hex_decrypted = ""
        self.conn = None
        self.iv = ""
        self.db_file = os.path.join(os.path.dirname(__file__), "sql_ndb_python.db")
        self.create_db_file()
        if self.conn is None:
            self.create_connection()

    def create_db_file(self):
        if not os.path.exists(self.db_file):
            with open(self.db_file, 'w') as fp:
                pass
            self.create_connection()
            cursor = self.conn.cursor()
            cursor.execute('''CREATE TABLE USER_DETAILS
                         ([user_id] INTEGER PRIMARY KEY,[user_name] text, [phone] text, [email] text, [password] text, 
                         [hash] BLOB, [ndb] BLOB, [enp] BLOB, [iv] BLOB) ''')
            self.close_file_conn()

    def gen_seq_of_symbols(self, perm_str):
        return "".join([self.symbols[perm_str[each: each + 2]] for each in range(0, len(perm_str)) if each < len(perm_str) - 1])

    def generate_hex(self, password):
        byte_pass = bytes(password, "utf-8")
        hash_256 = hashlib.sha256()
        hash_256.update(byte_pass)
        hex_digit = hash_256.hexdigest()
        self.hex = hex_digit

    def generate_ndb(self, password):
        self.generate_hex(password)
        binary_digit = bin(int(self.hex , 16))[2:].zfill(256)
        n_perm_str = binary_digit[::-1]
        sequence_of_symbols = self.gen_seq_of_symbols(n_perm_str)
        if sequence_of_symbols[-1] == "*":
            negate_perm = "".join([str(int(not(int(each)))) for each in n_perm_str])
            sequence_of_symbols = self.gen_seq_of_symbols(negate_perm)
        self.ndb_val = sequence_of_symbols

    def aes_encrypt(self, password, iv):
        private_key = hashlib.sha256(password.encode("utf-8")).digest()
        raw = self.pad(self.ndb_val)
        if iv is None:
            iv = Random.new().read(AES.block_size)
        cipher = AES.new(private_key, AES.MODE_CBC, iv)
        self.enp = base64.b64encode(iv + cipher.encrypt(raw))
        self.iv = iv

    def aes_encryption_double(self, password, raw, iv):
        private_key = hashlib.sha256(password.encode("utf-8")).digest()
        raw = self.pad(str(raw))
        if iv is None:
            iv = Random.new().read(AES.block_size)
        cipher = AES.new(private_key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def authentication(self, password, iv=None):
        self.generate_ndb(password)
        self.aes_encrypt(password, iv)
        return self.hex, self.ndb_val, self.enp, self.iv

    def create_connection(self):
        """ create a database connection to a SQLite database """
        try:
            self.conn = sqlite3.connect(self.db_file)
        except Error as e:
            print(e)

    def close_file_conn(self):
        if self.conn:
            self.conn.close()
            self.conn = None

    def insert_user_details(self, user_id, user_name, phone_no, email_id, pass_word, hashed, ndb, enp, iv):
        query = """INSERT INTO USER_DETAILS(user_id,user_name,phone, email, password, hash, ndb, enp, iv)
              VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)"""
        cur = self.conn.cursor()
        cur.execute(query, (user_id,user_name, phone_no, email_id, pass_word, hashed, ndb, enp, iv))
        self.conn.commit()
        out = cur.lastrowid
        self.close_file_conn()
        return out

    def query_data(self, user_id):
        query = """select * from USER_DETAILS where user_id = {}""".format(str(user_id))
        cur = self.conn.cursor()
        cur.execute(query)
        res = cur.fetchone()
        self.close_file_conn()
        return res


@app.route('/register', methods = ['POST'])
def register_user_details():
    """
    """
    if request.headers['Content-Type'] == 'application/json':
        try:
            user_input = json.loads(request.data.decode(encoding='UTF-8'))
            ens_obj = ENP()
            hex_, ndb, enp, iv = ens_obj.authentication(user_input["password"])
            enp_double = ens_obj.aes_encryption_double(user_input["password"], enp, iv)
            id = ens_obj.insert_user_details(user_input["id"], user_input["name"], user_input["phone"],
                                             user_input["email"], user_input["password"], hex_, ndb,enp_double, iv)
            status = True
            remarks = str(id)
        except Exception as error:
            status = False
            remarks = error
            print(traceback.print_exc())
        return jsonify({"status": status, "remarks": str(remarks)})
    else:
        return jsonify({'status': False, 'remarks':'Content type != application/json'})


@app.route('/verify', methods = ['GET'])
def verify_user_details():
    """
    """
    try:
        user_id = request.args.get('id')
        password = request.args.get('password')
        ens_obj = ENP()
        res_ = ens_obj.query_data(int(user_id))
        if not res_:
            raise Exception("User ID is not available")
        user_enp = res_[7]
        iv = res_[8]
        hex_, ndb, enp, iv = ens_obj.authentication(password, iv)
        enp_double = ens_obj.aes_encryption_double(password, enp, iv)
        status = user_enp == enp_double
        remarks = "Same Password" if status else "Password Mismatch"
    except Exception as error:
        status = False
        remarks = error
    return jsonify({"status": status, "remarks": str(remarks)})


if __name__ == '__main__':
    app.run(port = int(os.getenv("PORT", 5000)), debug=True)
