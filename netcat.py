#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import base64
import hashlib
import os
import shlex
import socket
import struct
import json
import subprocess
import sys
import textwrap
import threading

from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import PKCS1_v1_5


def readpri():
    # 从 PEM 格式私钥文件中读取私钥
    # 从私钥文件中读取私钥
    # pri_key = RSA.import_key(f)
    with open("pri.pem", "r") as f:
        pri_key = str(f.read()).replace("-----BEGIN RSA PRIVATE KEY-----", "").replace("-----END RSA PRIVATE KEY-----",
                                                                                       "").replace("\r\n", "").replace(
            "\n", "").replace("\r", "")
    return pri_key


def execute(cmd):
    # 除去两端的指定字符，strip()默认为除去空格,这里去除用于命令结束的kk字符
    cmd = cmd.strip('kk')
    if not cmd:
        return
    # shlex.split用类似 shell 的语法拆分字符串cmd，仅适用于Unix shell stderr=subprocess.STDOUT同时收集错误输出
    # check_output 执行命令，以byte字符串返回执行的结果
    output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)
    # output = subprocess.run(shlex.split(cmd),shell=True)
    # Popen 编码问题
    # output = subprocess.Popen(shlex.split(cmd),shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    # 读取执行结果
    # result = output.stdout.read() + output.stderr.read()
    return output.decode()


# 通信加密传输？
# 服务端发送公钥给客户端，客户端利用公钥加密随机对称秘钥如随机时间等，后服务器使用私钥解密随机对称秘钥，过后利用随机对称秘钥传输数据
class Config:
    # 是否需要-----BEGIN RSA PRIVATE KEY-----
    # -----END RSA PRIVATE KEY-----
    SERVER_PUBLIC_KEY = '''MIIBCgKCAQEA3PhDjcjpLTxl2YGfgMhsXt7SCPwhdcOoLr6LOy1hYOEJNVZRIpjV
pC1OZkI+VjkBpa/CYdcPPR4vs/s5gkGM8vxNLZtorF99N0P2XJ2ANZw6+diU9Rrt
HzMagZ3px4gEJAj7kqkBkwuI5wN3qIot03Gy5Phd9vctHs/OuYKlKelYXeAzDpaj
88gbzB3KzfCA5WeXxHV5ciITX15yTgJ2jmCdNAPVDlxxVajWBbXtxvuHb2YLHExL
YU9CbroZPaZu0lO8Ui4IfaM6A+k7C8AMRpvHKdYuGr/K12r19wPlapAG3o14lKno
+uX+IFCXrEmK2wWwYXEpOFe27mQKx5TeWwIDAQAB'''
    SERVER_PRIVATE_KEY = readpri()


class RSACipher():
    """
    RSA加密、解密、签名、验签工具类
    """

    def encrypt(self, key, raw):
        """
        加密方法
        :param key: 公钥
        :param raw: 需要加密的明文 bytes
        :return: base64编码的密文 bytes
        """
        public_key = RSA.importKey(base64.b64decode(key))
        cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        return base64.b64encode(cipher.encrypt(raw))

    def decrypt(self, key, enc):
        """
        解密方法
        :param key: 私钥
        :param enc: base64编码的密文 bytes
        :return: 解密后的明文 bytes
        """
        private_key = RSA.importKey(base64.b64decode(key))
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        return cipher.decrypt(base64.b64decode(enc))

    def sign(self, key, text):
        """
        签名方法
        :param key: 私钥
        :param text: 需要签名的文本 bytes
        :return: base64编码的签名信息 bytes
        """
        private_key = RSA.importKey(base64.b64decode(key))
        hash_value = SHA256.new(text)
        signer = PKCS1_v1_5.new(private_key)
        signature = signer.sign(hash_value)
        return base64.b64encode(signature)

    def verify(self, key, text, signature):
        """
        验签方法
        :param key: 公钥
        :param text: 需要验签的文本 bytes
        :param signature: base64编码的签名信息 bytes
        :return: 验签结果 bool
        """
        public_key = RSA.importKey(base64.b64decode(key))
        hash_value = SHA256.new(text)
        verifier = PKCS1_v1_5.new(public_key)
        return verifier.verify(hash_value, base64.b64decode(signature))


class AESCipher:
    """
    AES加密、解密工具类
    """

    def __init__(self, key):
        self.key = key
        # 这里直接用key充当iv
        self.iv = key

    def encrypt(self, raw):
        """
        加密方法
        :param raw: 需要加密的密文 str
        :return: base64编码的密文 str
        """
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return base64.b64encode(cipher.encrypt(self.__pad(raw).encode())).decode()

    def decrypt(self, enc):
        """
        解密方法
        :param enc: base64编码的密文 str
        :return: 解密后的明文 str
        """
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return self.__unpad(cipher.decrypt(base64.b64decode(enc)).decode())

    def __pad(self, text):
        # 填充方法，加密内容必须为16字节的倍数
        text_length = len(text)
        amount_to_pad = AES.block_size - (text_length % AES.block_size)
        if amount_to_pad == 0:
            amount_to_pad = AES.block_size
        pad = chr(amount_to_pad)
        return text + pad * amount_to_pad

    def __unpad(self, text):
        # 截取填充的字符
        pad = ord(text[-1])
        return text[:-pad]


class Header:
    def __init__(self, aes_cmd):
        # 判断是否是输入命令
        if not aes_cmd:
            self.header = {
                'hash': None,
                'total_size': None,
            }
        if aes_cmd == 'f':
            self.file_path = input("input上传文件路径:")
            hash256, file_name, total_size = self.get_file(self.file_path)
            # 自定义报头 固定长度的字节数
            self.header = {
                'hash': hash256,
                'file_name': f'{file_name}',
                'total_size': total_size,
            }
        else:
            hash256 = self.str_sha256(aes_cmd)
            aes_cmd_bytes = aes_cmd.encode('utf-8')
            total_size = len(aes_cmd_bytes)
            self.header = {
                'hash': hash256,
                'aes_cmd': aes_cmd,
                'total_size': total_size,
            }

    def get_file(self, file_path: str):
        h = hashlib.sha256()
        file_size = os.path.getsize(file_path)
        dir_name, full_file_name = os.path.split(file_path)
        if not os.path.isfile(file_path):
            print('文件不存在。')
            return ''
        with open(file_path, 'rb') as f:
            while b := f.read(8192):
                h.update(b)
        return h.hexdigest(), full_file_name, file_size

    def str_sha256(self, content: str) -> str:
        h = hashlib.sha256()
        # update数据为二进制bytes
        h.update(content.encode('utf-8'))
        return h.hexdigest()

    def send_header(self, conn):
        # 将dic进行json序列化
        header_json = json.dumps(self.header)
        # 将json数据encode到bytes格式
        header_json_bytes = header_json.encode('utf-8')
        # 获取header的总字节数
        len_header = len(header_json_bytes)
        # 将不固定长度的header的总字节数固定长度为4个字节
        four_head_bytes = struct.pack('i', len_header)
        # 发送的数据：（int 总字节数）4个字节 + header_json_bytes + 总数据bytes
        # header和总数据数据的大小不固定
        conn.send(four_head_bytes)
        conn.send(header_json_bytes)
        conn.send(self.header['aes_cmd'].encode('utf-8'))

    def unpack(self, conn):
        # 接收固定4字节len
        four_head_bytes = conn.recv(4)
        # 利用len解包出报头总字节数
        len_header = struct.unpack('i', four_head_bytes)[0]
        # 接收报头中的json数据
        header_json = conn.recv(len_header).decode('utf-8')
        # 将json数据反序列化成dic
        header = json.loads(header_json)
        total_data = b''
        while len(total_data) < header['total_size']:
            total_data += conn.recv(1)
        return total_data




class NetCat:
    # 构造函数，实例化时自动执行，传入参数args，buffer
    def __init__(self, args, buffer=None):
        # args为parse_args()解析的对象，参数为其属性值
        # args对象
        self.args = args
        # bytes
        self.buffer = buffer
        # 随机生成aes的密钥
        self.aes_key = get_random_bytes(16)
        # 生成aes加密器
        self.aes_cipher = AESCipher(self.aes_key)
        # 生成rsa加密器
        self.rsa_cipher = RSACipher()
        # 使用服务端公钥加密aes密钥
        self.encrypt_key = self.rsa_cipher.encrypt(Config.SERVER_PUBLIC_KEY, self.aes_key)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # 设置地址重用
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # 类方法必须包含参数 self, 且为第一个参数，self 代表的是类的实例。
    def run(self):
        if self.args.listen:
            self.listen()
        else:
            self.send()

    # 设置客户端发送数据函数
    def send(self):
        # 密文
        # self.buffer = self.aes_cipher.encrypt(self.buffer.decode())
        # 发送aes秘钥到服务端
        self.socket.connect((self.args.target, self.args.port))
        dic_obj = Header(self.encrypt_key.decode())
        if self.encrypt_key:
            dic_obj.send_header(self.socket)
        # 发送aes秘钥  接收res 打印res 输入命令 发送命令
        try:
            while 1:
                # 接收提示
                aes_k = dic_obj.unpack(self.socket)
                k = self.aes_cipher.decrypt(aes_k.decode())
                if k:
                    print(k)
                    # input默认接收str字符串
                    buffer = input('')
                    # 密文
                    smess = self.aes_cipher.encrypt(buffer)
                    dic_obj = Header(smess)
                    dic_obj.send_header(self.socket)
                # 接收响应
                response = dic_obj.unpack(self.socket)
                plaintext = self.aes_cipher.decrypt(response.decode())
                if plaintext:
                    print(plaintext)
        except KeyboardInterrupt:
            print('User terminated.')
            self.socket.close()
            sys.exit()

    # 设置服务端监听函数
    def listen(self):
        # 绑定服务端口
        self.socket.bind((self.args.target, self.args.port))
        # 设置最大连接数5
        self.socket.listen(5)
        # 开启conn多线程一个conn一个线程
        while True:
            # 接受客户端连接
            client_socket, addr = self.socket.accept()
            # 线程开启
            client_thread = threading.Thread(target=self.handle, args=(client_socket,))
            client_thread.start()

    # 线程作用函数 handle 传入参数client_socket
    def handle(self, client_socket):
        # 接收客户端发送的加密aes秘钥
        dic_obj = Header('')
        encrypt_key = dic_obj.unpack(client_socket)
        # 生成rsa加密器
        rsa_cipher = RSACipher()
        # 使用服务端私钥解密aes密钥
        aes_key = rsa_cipher.decrypt(Config.SERVER_PRIVATE_KEY, encrypt_key)
        # 生成aes加密器
        aes_cipher = AESCipher(aes_key)
        # ok = aes_cipher.encrypt('ok')
        # dic_obj = Header(ok)
        # dic_obj.send_header(client_socket)
        if self.args.execute:
            output = execute(self.args.execute)
            # 密文
            aes_output = aes_cipher.encrypt(output)
            dic_obj = Header(aes_output)
            dic_obj.send_header(client_socket)
        elif self.args.upload:
            file_buffer = b''
            while True:
                data = dic_obj.unpack(client_socket)
                # 解密
                data = aes_cipher.decrypt(data.decode()).encode()
                if data:
                    file_buffer += data
                else:
                    break
            with open(self.args.upload, 'wb') as f:
                f.write(file_buffer)
            message = f'Saved file {self.args.upload}'
            dic_obj = Header(aes_cipher.encrypt(message))
            dic_obj.send_header(client_socket)

        # c接收提示符 输入命令 发送命令 接收命令结果
        # s发送提示符 接收命令 发送执行结果
        elif self.args.command:
            plaintext = b''
            # 循环通信
            while True:
                try:
                    # 向客户端发送命令提示字符，表示可以执行命令
                    k = f'{aes_cipher.encrypt("<kk #>")}'
                    dic_obj = Header(k)
                    dic_obj.send_header(client_socket)
                    # while 循环判断kk命令结束符的存在
                    while 'kk' not in plaintext.decode():
                        # 接收客户端发送的命令
                        plaintext += dic_obj.unpack(client_socket)
                        plaintext = aes_cipher.decrypt(plaintext.decode()).encode()
                    response = execute(plaintext.decode())
                    if response:
                        # 将命令结果发送给客户端
                        response = aes_cipher.encrypt(response)
                        dic_obj = Header(response)
                        dic_obj.send_header(client_socket)
                    plaintext = b''
                except Exception as e:
                    print(f'server killed {e}')
                    self.socket.close()
                    sys.exit()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='python nc tool',
        # 格式化输出帮助文档的一个类 会将 description 和 epilog 的文字在命令行中自动换行
        formatter_class=argparse.RawDescriptionHelpFormatter,
        # textwrap.dedent(text)从文本的每一行中删除任何常见的前导空格。（'''使回车会自动转化为 \n）三引号的字符串与显示的左边缘对齐，同时仍然以缩进的形式在源代码中显示它们。
        epilog=textwrap.dedent('''Example:
			netcat.py -t 192.168.1.108 -p 5555 -l -c # open a command shell
			netcat.py -t 192.168.1.108 -p 5555 -l -u=mytest.txt #upload to file
			netcat.py -t 192.168.1.108 -p 5555 -l -e=\"cat /etc/passwd\" #execute command
			echo 'ABC' | ./netcat.py -t 192.168.1.108 -p 135 # echo text to server port 135
			netcat.py -t 192.168.1.108 -p 5555 #connect to server
			'''))
    parser.add_argument('-c', '--command', action='store_true', help='command shell')
    parser.add_argument('-e', '--execute', help='execute specified command')
    parser.add_argument('-l', '--listen', action='store_true', help='listen')
    parser.add_argument('-p', '--port', type=int, default=5555, help='specified port')
    parser.add_argument('-t', '--target', default='192.168.1.203', help='specified IP')
    parser.add_argument('-u', '--upload', help='upload file')
    # 参数由parse_args()解析。 解析的参数作为对象属性存在。
    args = parser.parse_args()
    if args.listen:
        buffer = ''
    else:
        # sys.stdin—一个类似对象的文件—调用sys.stdin.read()来读取所有内容。读取标准输入内容
        buffer = sys.stdin.read()
        # 读取标准输出内容
        # buffer = sys.stdout.read()
        # buffer = sys.stderr.read()

    nc = NetCat(args, buffer.encode())
    nc.run()
