# StegoVault PNG Steganography Tool

StegoVault is a cross-platform Python GUI tool for hiding encrypted secret messages inside PNG images using LSB steganography.

<img width="363" height="332" alt="Screenshot 2026-05-02 at 21 25 00" src="https://github.com/user-attachments/assets/fbdcc419-8979-424b-92c0-8031bf727c4f" />
<img width="362" height="117" alt="Screenshot 2026-05-02 at 21 25 19" src="https://github.com/user-attachments/assets/b1e1dca1-c041-4408-93b5-87715c2c84da" />

## Features
- Hide secret messages inside PNG images
- Extract hidden messages from encoded PNG images
- Password-based encryption before embedding
- LSB steganography using RGB channels
- Mac and Windows friendly GUI
- Scrollable interface for better usability
- Drag and drop support for decryption flow
- Capacity indicator for message size
- Password confirmation before encoding
- Overwrite warning when saving encoded images
- Clipboard copy for extracted messages

## How To Use: 
https://github.com/khucker3d/cyber-stegovault-png-steganography-tool/blob/main/How%20to%20Use.md


## Steganography Method
- This tool uses spatial-domain LSB steganography.
- The hidden encrypted payload is stored in the least significant bits of the RGB color channels of each pixel.
- Each pixel can store 3 bits:
  - Red channel stores 1 bit
  - Green channel stores 1 bit
  - Blue channel stores 1 bit
- The alpha channel is preserved.

## Security Layer
Before the message is embedded, it is encrypted using password-based symmetric encryption.

The tool uses:
- PBKDF2 for password-based key derivation
- Fernet symmetric encryption from the Python cryptography library
- Random salt for each encoded message

This means that even if hidden data is extracted, the message still requires the correct password to decrypt.
