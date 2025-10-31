# For Encryption:
python encryption_win.py "C:\Users\John\Documents" "C:\Users\John\Pictures" "C:\keys\secret.key"

# To Restore:

# 1. Extract ZIPs (using same password)
unzip -P "yourpassword" /home.zip -d /tmp/restored_home/
unzip -P "yourpassword" /root.zip -d /tmp/restored_root/

# 2. Decrypt files
python3 decryption.py /tmp/restored_home /tmp/restored_root /tmp/ransom.key
