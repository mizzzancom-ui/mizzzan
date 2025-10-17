import base64
import hashlib
import hmac
import json
import requests
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from pathlib import Path

# ---- Replace this with your webhook JSON ----
webhook_json = """
[
    {
        "event": "messages.received",
        "sessionId": "055cc8578095fd053bd96c2b68f3105625e0bd14a3e2c6555399ebeea45d233d",
        "data": {
            "messages": {
                "key": {
                    "remoteJid": "966541924450@s.whatsapp.net",
                    "fromMe": false,
                    "id": "3A70ECEB6E87BC4BD7C8",
                    "senderLid": "141055534075980@lid"
                },
                "messageTimestamp": 1760692357,
                "pushName": "RaKaN ~",
                "broadcast": false,
                "message": {
                    "imageMessage": {
                        "url": "https://mmg.whatsapp.net/o1/v/t24/f2/m235/AQPhUTPI453NgClhK5eMudlEg4f8sIqEW7wK0KrAVSZkTy9cC3YKGYrplnxtkLYShKbIm_aMv0GcyeLzP_bq6At8V-eafQHmhhGD914JBA?ccb=9-4&oh=01_Q5Aa2wGR9-VJS7kVY3Q2e7zXr-RY21lblJFsm1yQCmvYBJL4hQ&oe=691975CD&_nc_sid=e6ed6c&mms3=true",
                        "mimetype": "image/jpeg",
                        "fileSha256": "KB+utSG4p6Z7A+aqE6cQO9zl0RqR05L1PLV77ftipkQ=",
                        "fileLength": "38198",
                        "height": 1600,
                        "width": 738,
                        "mediaKey": "v8YTGa843ZNgputzggBWhX3FrW7YsssuBUrrjPiHsdE=",
                        "fileEncSha256": "2FB/uVREBuRvX9WwbIBaI0hDlmrA/AF4aO62XUWLwSs=",
                        "directPath": "/o1/v/t24/f2/m235/AQPhUTPI453NgClhK5eMudlEg4f8sIqEW7wK0KrAVSZkTy9cC3YKGYrplnxtkLYShKbIm_aMv0GcyeLzP_bq6At8V-eafQHmhhGD914JBA?ccb=9-4&oh=01_Q5Aa2wGR9-VJS7kVY3Q2e7zXr-RY21lblJFsm1yQCmvYBJL4hQ&oe=691975CD&_nc_sid=e6ed6c",
                        "mediaKeyTimestamp": "1760692344",
                        "jpegThumbnail": "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDABsSFBcUERsXFhceHBsgKEIrKCUlKFE6PTBCYFVlZF9VXVtqeJmBanGQc1tdhbWGkJ6jq62rZ4C8ybqmx5moq6T/2wBDARweHigjKE4rK06kbl1upKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKT/wgARCABIAEgDASIAAhEBAxEB/8QAGQABAAMBAQAAAAAAAAAAAAAAAAMEBQEC/8QAGAEBAQEBAQAAAAAAAAAAAAAAAAEDBAX/2gAMAwEAAhADEAAAAIBKARyQFACGxRr8JJao2JsPWJga8WyMFvcMJudMKTa4ZbUHRSGaPO0rlS3x7Sj0MAAAPHsgKA//xAAdEQEAAQMFAAAAAAAAAAAAAAABAgARMAMEECAx/9oACAECAQE/AOBviEfOmoXilbeNp4P/xAAbEQABBAMAAAAAAAAAAAAAAAABAAIwMQMQEf/aAAgBAwEBPwDRHJm2slQf/8QAKxAAAQMCAgoBBQAAAAAAAAAAAQACAwQREiAFBhAWISIxQVFTMBRDUmGB/9oACAEBAAE/APlxuxWtnnqGQjibnwpK6Vx5eUL6iX8uKjrpWnm5goKhkw4Gx8ZKmYQx37nonuL3FzjclHaxxY4OabEKmmE0d+467I9DtLAXvOL9Ko1ehnILpXCy3Xp/a5br0/tct16f2uQ1Xpx95y3Xp/a5QavQwEkSusn6IbgJjeSe2QkDqsbfI2kXFigABYdMlSeRYiqcuLOP8zztLoyAsLvBVOCI7EW+AyRiQRlwxniBl//+AAMA/9k=",
                        "contextInfo": {
                            "statusSourceType": "IMAGE"
                        },
                        "firstScanSidecar": "EZdJkyTZZ/46kA==",
                        "firstScanLength": 5833,
                        "scansSidecar": "EZdJkyTZZ/46kKEC4xI0/drHHDc4jPw7vZA0icQMvBtAM9w3bMzgYw==",
                        "scanLengths": [
                            5833,
                            18066,
                            5062,
                            9235
                        ],
                        "midQualityFileSha256": "9/utsSQBpEPBgKKEOxDrd0/QFlsrpOkxZaHJ9gfVQMI=",
                        "imageSourceType": "USER_IMAGE"
                    },
                    "messageContextInfo": {
                        "deviceListMetadata": {
                            "senderKeyHash": "AtDnXxnsxNcIOg==",
                            "senderTimestamp": "1760037089",
                            "recipientKeyHash": "6bV3yPH7a4cVDg==",
                            "recipientTimestamp": "1759586387"
                        },
                        "deviceListMetadataVersion": 2,
                        "messageSecret": "+1LCYI33rEszP6FZopqatNbcUHkyhWL5zE4CnFHlA9g="
                    }
                },
                "remoteJid": "966541924450@s.whatsapp.net",
                "id": "3A70ECEB6E87BC4BD7C8"
            }
        },
        "timestamp": 1760692357903
    }
]
"""

data = json.loads(webhook_json)[0]["data"]["messages"]["message"]["imageMessage"]

# Extract required fields
url = data["url"]
media_key_b64 = data["mediaKey"]
file_enc_sha256_b64 = data["fileEncSha256"]
mime = data["mimetype"]

# Download encrypted media from WhatsApp
print("Downloading encrypted media...")
resp = requests.get(url, stream=True)
enc_data = resp.content

# WhatsApp encrypted files have a 10-byte MAC appended
enc_data_no_mac = enc_data[:-10]
mac_tail = enc_data[-10:]

# Derive keys from mediaKey using HKDF-SHA256
media_key = base64.b64decode(media_key_b64)
salt = bytes([0]*32)
info = b"WhatsApp Image Keys"

hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=112,
    salt=salt,
    info=info,
    backend=default_backend()
)
derived = hkdf.derive(media_key)
iv = derived[0:16]
cipher_key = derived[16:48]
mac_key = derived[48:80]

# Validate MAC (first 10 bytes of HMAC-SHA256 over IV + ciphertext)
calc_mac_full = hmac.new(mac_key, iv + enc_data_no_mac, hashlib.sha256).digest()
if calc_mac_full[:10] != mac_tail:
    raise ValueError("MAC verification failed! File may be corrupted.")

# AES-CBC decrypt
cipher = Cipher(algorithms.AES(cipher_key), modes.CBC(iv), backend=default_backend())
decryptor = cipher.decryptor()
plaintext_padded = decryptor.update(enc_data_no_mac) + decryptor.finalize()

# Remove PKCS7 padding
unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
plaintext = unpadder.update(plaintext_padded) + unpadder.finalize()

# Optional: verify fileEncSha256
reported_file_enc_sha256 = base64.b64decode(file_enc_sha256_b64)
sha_with_mac = hashlib.sha256(enc_data).digest()
print("fileEncSha256 match:", sha_with_mac == reported_file_enc_sha256)

# Save decrypted image
ext = ".jpg" if "jpeg" in mime else ".png"
output_path = Path(f"decrypted_image{ext}")
output_path.write_bytes(plaintext)

print(f"✅ Image decrypted and saved to: {output_path.resolve()}")
