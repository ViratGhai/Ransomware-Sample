# For Encryption (Linux):
python3 Encryption_Linux.py /home/user/Documents /home/user/Pictures /tmp/secret.key

# To Restore:

# 1. Extract ZIPs (using same password)
unzip -P "yourpassword" /home/user/Documents.zip -d /tmp/restored_docs/
unzip -P "yourpassword" /home/user/Pictures.zip -d /tmp/restored_pics/

# 2. Decrypt files
python3 Decryption_Linux.py /tmp/restored_docs /tmp/restored_pics /tmp/secret.key
