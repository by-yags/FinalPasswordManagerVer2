import pyotp
import qrcode
from PIL import Image

def generate_secret():
    """Generate a new 2FA secret."""
    return pyotp.random_base32()

def get_provisioning_uri(secret, username, issuer_name="PasswordManager"):
    """Get the provisioning URI for the authenticator app."""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer_name)

def verify_otp(secret, otp):
    """Verify the one-time password."""
    totp = pyotp.TOTP(secret)
    return totp.verify(otp)

def generate_qr_code(uri, filename="2fa_qr.png"):
    """Generate a QR code from the provisioning URI."""
    img = qrcode.make(uri)
    img.save(filename)
    return filename