import boto3 
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# AWS Configurations 
S3_BUCKET = "eden-xxxxxxxx-bucket"
S3_OBJECT_KEY = "encrypted_data.txt"
DECRYPTED_FILE_PATH = "decrypted_data.txt"

# Initialize AWS Clients
kms_client = boto3.client('kms')
s3_client = boto3.client('s3')

# Step 1: Download encrypted file from S3
response = s3_client.get_object(Bucket=S3_BUCKET, Key=S3_OBJECT_KEY)
encrypted_data = response['Body'].read()
encrypted_dek = response['Metadata']['encrypted-dek'] # Retrieve encrypted DEK

# Step 2: Decrypt the DEK
decrypted_key_response = kms_client.decrypt(CiphertextBlob=base64.b64decode(encrypted_dek))
decrypted_key = decrypted_key_response['Plaintext']

# Step 3: Decrypt the file
def decrypt_file(encrypted_data, key):
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Optional: Remove padding if applied during encryption
    # Ensure this matches the padding scheme used for encryption
    decrypted_data = decrypted_data.rstrip(b'\x00')  # Replace with correct padding removal

    return decrypted_data  # Added return statement

# Call decrypt_file
decrypted_content = decrypt_file(encrypted_data, decrypted_key)

# Step 4: Save the decrypted file
with open(DECRYPTED_FILE_PATH, 'wb') as outfile:
    outfile.write(decrypted_content)


print(f"File decrypted and saved to {DECRYPTED_FILE_PATH}")
