from certificates.utils import generate_key_pair, generate_csr, serialize_key, serialize_csr

print("Generating Key Pair...")
key = generate_key_pair()
pem_key = serialize_key(key)
print("Key Generated:")
print(pem_key[:50] + "...")

print("\nGenerating CSR for app1.example.com...")
csr = generate_csr(key, "app1.example.com", country="ES", organization="My Company")
pem_csr = serialize_csr(csr)
print("CSR Generated:")
print(pem_csr[:50] + "...")

print("\nTest Complete.")
