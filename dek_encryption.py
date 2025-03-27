import boto3
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# AWS Configurations
KMS_KEY_ARN = "arn:aws:kms:us-east-1:xxxxxxxxxxxxxxxxxxxx"  # Add Your KMS Key ARN
S3_BUCKET = "eden-xxxxxxxxx-bucket" # Add Your S3 Bucket
FILE_PATH = "data.txt"
ENCRYPTED_FILE_PATH = "encrypted_data.txt"

# Initialize AWS Clients
kms_client = boto3.client('kms')
s3_client = boto3.client('s3')

# Step 1: Generate Data Encryption Key (DEK)
response = kms_client.generate_data_key(KeyId=KMS_KEY_ARN, KeySpec='AES_256')
plaintext_key = response['Plaintext']  # This key should be stored securely
encrypted_key = base64.b64encode(response['CiphertextBlob']).decode('utf-8') 

# Step 2: Encrypt the File 
def encrypt_file(input_path, output_path, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_path, 'rb') as infile:
        file_data = infile.read()

    # Padding for AES block size (16 bytes)
    padding_length = 16 - (len(file_data) % 16)
    file_data += bytes([padding_length] * padding_length)

    encrypted_data = encryptor.update(file_data) + encryptor.finalize()

    # Save IV + Encrypted Data
    with open(output_path, 'wb') as outfile:
        outfile.write(iv + encrypted_data)

encrypt_file(FILE_PATH, ENCRYPTED_FILE_PATH, plaintext_key)

# Step 3: Upload Encrypted File to S3 with Encrypted DEK as Metadata
with open(ENCRYPTED_FILE_PATH, 'rb') as encrypted_file:
    s3_client.put_object(
        Bucket=S3_BUCKET,
        Key=ENCRYPTED_FILE_PATH,
        Body=encrypted_file,
        Metadata={'encrypted-dek': encrypted_key}
    )

print(f"Encrypted file uploaded successfully to s3://{S3_BUCKET}/encrypted-data.txt")
