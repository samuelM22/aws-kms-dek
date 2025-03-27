      Encrypt Files Before Storing in S3 with AWS KMS 
This Project will guide you through encrypting files before uploading them to Amazon S3 by:

Generating a Data Encryption Key (DEK) using AWS KMS

Encrypting the file locally with the DEK

Uploading the encrypted file to S3 and storing the encrypted DEK as metadata

🛠 Prerequisites
✅ AWS CLI installed and configured
✅ Python 3.x installed with required libraries
✅ An AWS KMS Key available (or create a new one)
✅ An S3 Bucket for storing the encrypted file

📌 Step 1: Create a KMS Key for Encryption
You need an AWS KMS key to generate a Data Encryption Key (DEK).

1.1 Create a KMS Key (If not already available)

aws kms create-key --description "S3 File Encryption Key" --key-usage ENCRYPT_DECRYPT --customer-master-key-spec SYMMETRIC_DEFAULT
This returns a Key ID and ARN. Copy the Key ARN for later use.

To list available keys:

aws kms list-keys
To describe a specific key:

aws kms describe-key --key-id <key-id>
📌 Step 2: Generate a Data Encryption Key (DEK)
A DEK (Data Encryption Key) is generated using AWS KMS.
This key is used for encrypting the file locally.

2.1 Generate DEK using KMS
aws kms generate-data-key --key-id <KMS-KEY-ARN> --key-spec AES_256
This returns:

CiphertextBlob (Encrypted DEK - store this safely)

Plaintext (DEK - Use this to encrypt the file)

📌 Step 3: Encrypt the File Locally
We will use Python with Cryptography library to:

Encrypt the file using the plaintext DEK

Base64 encode the encrypted DEK for S3 metadata storage

3.1 Install Required Python Packages

pip install boto3 cryptography base64
3.2 Python Script to Encrypt and Upload File
python
Copy
Edit
import boto3
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# AWS Configurations
KMS_KEY_ARN = "<YOUR_KMS_KEY_ARN>"
S3_BUCKET = "<YOUR_S3_BUCKET_NAME>"
FILE_PATH = "data.txt"  # File to encrypt
ENCRYPTED_FILE_PATH = "data_encrypted.txt"

# Initialize AWS Clients
kms_client = boto3.client("kms")
s3_client = boto3.client("s3")

# Step 1: Generate Data Encryption Key (DEK)
response = kms_client.generate_data_key(KeyId=KMS_KEY_ARN, KeySpec="AES_256")
plaintext_key = response["Plaintext"]  # Use this to encrypt file
encrypted_key = base64.b64encode(response["CiphertextBlob"]).decode("utf-8")  # Store this safely

# Step 2: Encrypt the File
def encrypt_file(input_path, output_path, key):
    iv = os.urandom(16)  # Initialization Vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_path, "rb") as infile:
        file_data = infile.read()

    # Padding for AES block size (16 bytes)
    padding_length = 16 - (len(file_data) % 16)
    file_data += bytes([padding_length] * padding_length)

    encrypted_data = encryptor.update(file_data) + encryptor.finalize()

    # Save IV + Encrypted Data
    with open(output_path, "wb") as outfile:
        outfile.write(iv + encrypted_data)

encrypt_file(FILE_PATH, ENCRYPTED_FILE_PATH, plaintext_key)

# Step 3: Upload Encrypted File to S3 with Encrypted DEK as Metadata
with open(ENCRYPTED_FILE_PATH, "rb") as encrypted_file:
    s3_client.put_object(
        Bucket=S3_BUCKET,
        Key="encrypted-data.txt",
        Body=encrypted_file,
        Metadata={"encrypted-dek": encrypted_key}  # Store Encrypted DEK as metadata
    )

print(f"Encrypted file uploaded successfully to s3://{S3_BUCKET}/encrypted-data.txt")

📌 Step 4: Verify the Upload in S3
After running the script:

Go to the AWS S3 Console

Navigate to the Bucket

Find encrypted-data.txt

Click Properties → Metadata
You should see the encrypted-dek stored.

📌 Step 5: Download and Decrypt the File
To download and decrypt, we:

Fetch the encrypted file from S3

Retrieve the encrypted DEK from metadata

Decrypt the DEK using AWS KMS

Use the plaintext DEK to decrypt the file

Python Script to Decrypt File
python
Copy
Edit
import boto3
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# AWS Configurations
S3_BUCKET = "<YOUR_S3_BUCKET_NAME>"
S3_OBJECT_KEY = "encrypted-data.txt"
DECRYPTED_FILE_PATH = "data_decrypted.txt"

# Initialize AWS Clients
kms_client = boto3.client("kms")
s3_client = boto3.client("s3")

# Step 1: Download Encrypted File from S3
response = s3_client.get_object(Bucket=S3_BUCKET, Key=S3_OBJECT_KEY)
encrypted_data = response["Body"].read()
encrypted_dek = response["Metadata"]["encrypted-dek"]  # Retrieve encrypted DEK

# Step 2: Decrypt DEK using KMS
decrypted_key_response = kms_client.decrypt(CiphertextBlob=base64.b64decode(encrypted_dek))
decrypted_key = decrypted_key_response["Plaintext"]

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

print(f"Decrypted file saved at: {DECRYPTED_FILE_PATH}")
✅ Summary
Step	Action
Step 1	Generate DEK using AWS KMS
Step 2	Encrypt the file using the plaintext DEK
Step 3	Upload the encrypted file to S3, storing the encrypted DEK as metadata
Step 4	Verify the file and metadata in S3
Step 5	Download and decrypt the file using AWS KMS
