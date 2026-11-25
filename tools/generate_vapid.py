"""Generates a VAPID key pair for Web Push.  Run once:  python tools/generate_vapid.py
Needs: pip install cryptography
Put the 3 printed values in Vercel -> Settings -> Environment Variables, then redeploy.
Keep VAPID_PRIVATE_KEY secret. Do NOT change the keys later, or every user must re-enable notifications."""
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')


key = ec.generate_private_key(ec.SECP256R1())
private = key.private_numbers().private_value.to_bytes(32, 'big')
public = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
print('VAPID_PUBLIC_KEY=' + b64(public))
print('VAPID_PRIVATE_KEY=' + b64(private))
print('VAPID_SUBJECT=mailto:your-email@example.com')
