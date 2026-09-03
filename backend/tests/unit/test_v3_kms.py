import os
import sys

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.security.kms_envelope import MultiTenantKMSManager



def test_kms_envelope_encryption_decryption():
    kms = MultiTenantKMSManager()
    org_a = "tenant-org-alpha"
    
    # 1. Generate keys for Tenant A
    raw_dek, encrypted_dek = kms.generate_tenant_keys(org_a)
    assert len(raw_dek) == 32  # 256 bits
    import base64
    assert b"-wrapped-by-kek-" in base64.b64decode(encrypted_dek)


    # 2. Encrypt sample telemetry payload
    sample_payload = '{"event": "SSH Login", "user": "root", "src_ip": "10.0.0.1"}'
    ciphertext = kms.encrypt_payload(sample_payload, raw_dek, org_a)
    assert ciphertext != sample_payload

    # 3. Decrypt with valid tenant context
    decrypted = kms.decrypt_payload(ciphertext, encrypted_dek.decode(), org_a)
    assert decrypted == sample_payload


def test_cross_tenant_isolation_fails():
    kms = MultiTenantKMSManager()
    org_a = "tenant-org-alpha"
    org_b = "tenant-org-bravo"

    # Encrypt payload for Tenant A
    raw_dek_a, encrypted_dek_a = kms.generate_tenant_keys(org_a)
    raw_dek_b, encrypted_dek_b = kms.generate_tenant_keys(org_b)
    
    sample_payload = '{"secret": "classified-threat-telemetry"}'
    ciphertext_a = kms.encrypt_payload(sample_payload, raw_dek_a, org_a)

    # Attempt to decrypt Tenant A's ciphertext using Tenant B's DEK / org context
    failed_cross = False
    try:
        kms.decrypt_payload(ciphertext_a, encrypted_dek_b.decode(), org_b)
    except Exception:
        failed_cross = True
    assert failed_cross is True

    # Attempt to use Tenant A's encrypted DEK but passed as Tenant B
    failed_perm = False
    try:
        kms.decrypt_payload(ciphertext_a, encrypted_dek_a.decode(), org_b)
    except PermissionError:
        failed_perm = True
    assert failed_perm is True
