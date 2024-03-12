### Encryptor 
Encryptor is a simple go program that encrypts and decrypts files using AES 256 encryption algorithm.  

### Usage
```bash
go build -o encryptor
./encryptor -m e secret.txt secret.enc.txt
./encryptor -m d secret.enc.txt secret.dec.txt
```

### Options
```bash
-m: Mode of operation (e: encrypt, d: decrypt)
INPUT postional argument: Input file
OUTPUT postional argument: Output file
```
