# For Encryption (Windows):
python encryption_win.py "C:\Users\John\Documents" "C:\Users\John\Pictures" "C:\keys\secret.key"

# To Restore:

# Step 1: Extract ZIPs (using 7-Zip, WinRAR, etc.)
7z x "C:\Users\John\Documents.zip" -o"C:\restore\docs" -p"YourPassword"
7z x "C:\Users\John\Pictures.zip" -o"C:\restore\pics" -p"YourPassword"

# Step 2: Decrypt
python Decryption_Windows.py "C:\restore\docs" "C:\restore\pics" "C:\keys\secret.key"

# For exe conversion:

pip install pyinstaller
pyinstaller --onefile encryption_win.py
pyinstaller --onefile Decryption_Windows.py
