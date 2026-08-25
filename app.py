from flask import Flask, request, jsonify
import requests
import urllib3
import base64
import json
from Crypto.Cipher import AES
from google.protobuf.json_format import MessageToDict
from proto import FreeFire_pb2
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
app = Flask(__name__)
app.json.sort_keys = False
http_session = requests.Session()
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
FF_NICKNAME_KEY = b"1e5898ccb8dfdd921f9bdea848768b64a201"
def pad(text: bytes) -> bytes:
    padding_length = 16 - (len(text) % 16)
    return text + bytes([padding_length] * padding_length)
def encrypt(plaintext: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(plaintext))
def decode_ff_nickname(encoded: str) -> str:
    try:
        raw = base64.b64decode(encoded)
        dec = bytearray()
        for i, b in enumerate(raw):
            dec.append(b ^ FF_NICKNAME_KEY[i % len(FF_NICKNAME_KEY)])
        return dec.decode('utf-8', errors='replace')
    except Exception:
        return "Unknown"
def extract_nickname_from_jwt(token: str) -> str:
    try:
        parts = token.split('.')
        if len(parts) >= 2:
            payload_b64 = parts[1]
            payload_b64 += '=' * ((4 - len(payload_b64) % 4) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode('utf-8'))
            if 'nickname' in payload and isinstance(payload['nickname'], str):
                return decode_ff_nickname(payload['nickname'])
    except Exception:
        pass
    return "Unknown"
@app.route('/token', methods=['GET'])
def guest_login():
    uid = request.args.get('uid')
    pw = request.args.get('password')
    if not uid or not pw:
        return jsonify({"status": "error", "message": "Missing parameters. Use /token?uid=xxx&pw=xxx"}), 400
    oauth_url = "https://100067.connect.garena.com/api/v2/oauth/guest/token:grant"
    payload = {
        "client_id": 100067,
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_type": 2,
        "password": pw,
        "response_type": "token",
        "uid": int(uid)
    }
    try:
        r = http_session.post(oauth_url, json=payload, timeout=8)
        auth_data = r.json()
        inner = auth_data.get("data", {})
        acc_token = inner.get("access_token")
        open_id = inner.get("open_id")
        if not acc_token or not open_id:
            return jsonify({"status": "error", "message": "Auth tokens not found"}), 401
        req_msg = FreeFire_pb2.LoginReq()
        req_msg.open_id = open_id
        req_msg.open_id_type = "4"
        req_msg.login_token = acc_token
        req_msg.orign_platform_type = "4"
        enc_data = encrypt(req_msg.SerializeToString())
        headers = {
            "X-GA": "v1 1",
            "ReleaseVersion": "OB54",
            "Content-Type": "application/octet-stream",
            "User-Agent": USERAGENT
        }
        resp = http_session.post("https://loginbp.ggpolarbear.com/MajorLogin", data=enc_data, headers=headers, verify=False, timeout=8)
        if resp.status_code == 200:
            res_msg = FreeFire_pb2.LoginRes()
            res_msg.ParseFromString(resp.content)
            major_dict = MessageToDict(res_msg, preserving_proto_field_name=True)
            token = major_dict.get('token', '')
            nickname = extract_nickname_from_jwt(token)
            return jsonify({"token": token, "nickname": nickname}), 200
        else:
            return jsonify({"status": "error", "message": f"MajorLogin failed with status {resp.status_code}"}), 502
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=25126)