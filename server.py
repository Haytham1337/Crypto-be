from flask import Flask,request
from flask.json import jsonify
import time
from base64 import b64encode
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Cipher import Blowfish
from Crypto.Cipher import DES
from struct import pack
from Crypto.Util.Padding import unpad
from flask_cors import CORS, cross_origin

def createRes(data,key,time):
    return  {
        "encData": data,
        "key":key,
        "time":time,
    }

def createResDecrypt(data):
    return  {
        "decData": data
    }

def createPad(blockSize,text):
    plen = blockSize - len(text) % blockSize
    padding = [plen]*plen
    padding = pack('b'*plen, *padding)
    return padding

def blowFishEnc(inputTetx,key):
    inputData = inputTetx.encode()
    padding = createPad(Blowfish.block_size,inputData)
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    start = time.time()
    encData = cipher.encrypt(inputData+padding)
    end = time.time()
    endTime = end-start
    result = b64encode(encData).decode('utf-8')
    return result, endTime

def blowFishDec(inputText,key):
    inputData =  b64decode(inputText)
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    pt = unpad(cipher.decrypt(inputData), Blowfish.block_size)
    return pt

def aesEnc(inputTetx,key):
    inputData = inputTetx.encode()
    padding = createPad(AES.block_size,inputData)
    cipher = AES.new(key, AES.MODE_ECB)
    start = time.time()
    encData = cipher.encrypt(inputData+padding)
    end = time.time()
    endTime = end-start
    result = b64encode(encData).decode('utf-8')
    return result, endTime

def aesDec(inputText,key):
    inputData =  b64decode(inputText)
    cipher = AES.new(key, AES.MODE_ECB)
    pt = unpad(cipher.decrypt(inputData), AES.block_size)
    return pt

def desEnc(inputTetx,key):
    inputData = inputTetx.encode()
    padding = createPad(DES.block_size,inputData)
    cipher = DES.new(key, DES.MODE_ECB)
    start = time.time()
    encData = cipher.encrypt(inputData+padding)
    end = time.time()
    endTime = end-start
    result = b64encode(encData).decode('utf-8')
    return result, endTime

def desDec(inputText,key):
    inputData =  b64decode(inputText)
    cipher = DES.new(key, DES.MODE_ECB)
    pt = unpad(cipher.decrypt(inputData), DES.block_size)
    return pt


app = Flask(__name__)

@app.route('/desenc', methods=['POST'])
@cross_origin()
def encDES():
    req_data = request.get_json()
    textForEnc = req_data['text']
    key = req_data['key']
    newKey = key.encode('utf-8')
    #userKey = b64encode(key).decode('utf-8')
    result,endTime = desEnc(textForEnc,newKey)
    res_data =  createRes(result,key,endTime)
    return jsonify(res_data)

@app.route('/desdec', methods=['POST'])
@cross_origin()
def decDES():
    req_data = request.get_json()
    textForDec = req_data['text']
    key = req_data['key']
    newKey = key.encode('utf-8')
    result = desDec(textForDec,newKey)
    res_data = createResDecrypt(result.decode())
    return jsonify(res_data)

@app.route('/blowfishenc', methods=['POST'])
@cross_origin()
def encBlow():
    req_data = request.get_json()
    textForEnc = req_data['text']
    key = req_data['key']
    newKey = key.encode('utf-8')
    #userKey = b64encode(key).decode('utf-8')
    result,endTime = blowFishEnc(textForEnc,newKey)
    res_data =  createRes(result,key,endTime)
    return jsonify(res_data)

@app.route('/blowfishdec', methods=['POST'])
@cross_origin()
def decBlow():
    req_data = request.get_json()
    textForDec = req_data['text']
    key = req_data['key']
    newKey = key.encode('utf-8')
    result = blowFishDec(textForDec,newKey)
    res_data = createResDecrypt(result.decode())
    return jsonify(res_data)

@app.route('/aesenc', methods=['POST'])
@cross_origin()
def encAES():
    req_data = request.get_json()
    textForEnc = req_data['text']
    key = req_data['key']
    newKey = key.encode('utf-8')
    #userKey = b64encode(key).decode('utf-8')
    result,endTime = aesEnc(textForEnc,newKey)
    res_data =  createRes(result,key,endTime)
    return jsonify(res_data)


@app.route('/aesdec', methods=['POST'])
@cross_origin()
def decAES():
    req_data = request.get_json()
    textForDec = req_data['text']
    key = req_data['key']
    newKey = key.encode('utf-8')
    result = aesDec(textForDec,newKey)
    res_data = createResDecrypt(result.decode())
    return jsonify(res_data)

if __name__ == '__main__':
    app.run()


