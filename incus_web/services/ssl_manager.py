import os
import logging
import datetime
from ipaddress import ip_address

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

logger = logging.getLogger(__name__)

def check_and_generate_ssl_cert(instance_path):
    CERT_FILE = os.path.join(instance_path, "cert.pem")
    KEY_FILE = os.path.join(instance_path, "key.pem")

    if not CRYPTOGRAPHY_AVAILABLE:
        logger.warning("缺少 'cryptography' 库，无法生成 SSL 证书。")
        return False, None

    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return True, (CERT_FILE, KEY_FILE)

    try:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(KEY_FILE, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        ])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            key.public_key()
        ).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost"), x509.IPAddress(ip_address("127.0.0.1"))]),
            critical=False,
        ).sign(key, hashes.SHA256())
        with open(CERT_FILE, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        return True, (CERT_FILE, KEY_FILE)
    except Exception as e:
        logger.error(f"生成自签名 SSL 证书时发生错误: {e}")
        return False, None