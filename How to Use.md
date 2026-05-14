## How to Use
<img width="663" height="632" alt="Screenshot 2026-05-02 at 21 25 00" src="https://github.com/user-attachments/assets/fbf841c2-e8cc-4d98-873d-3e181282a7e3" />
<img width="662" height="317" alt="Screenshot 2026-05-02 at 21 25 19" src="https://github.com/user-attachments/assets/a44841e3-c896-49a2-b920-58224c3e6071" />

### Prereqs:
1. Install Python dependencies: ```python -m pip install -r requirements.txt```
2. Run the Tool:
  * Mac: ```python3 stego_vault_gui.py```
  * Windows: ```python stego_vault_gui.py```
  *Note: I used IDLE to create and run the script*

### Hide a Message
1. Select an input PNG image.
2. Type the secret message.
3. Review the capacity indicator.
5. Enter a password.
6. Confirm the password.
7. Choose an output PNG path.
8. Click Hide Message.

### Extract a Message
1. Select or drag and drop the encoded PNG image.
2. Enter the password used during encoding.
3. Click Extract Message.
4. Read or copy the decrypted message.

## Results: Original vs Encoded Image
*Original Image: StarryNight.png*

### File Name: StarryNight.png
<img width="512" height="512" alt="StarryNight" src="https://github.com/user-attachments/assets/355fd4e8-4bb9-4921-9bf0-8e6698d2be7b" />
<img width="430" height="656" alt="Screenshot 2026-05-02 at 21 15 47" src="https://github.com/user-attachments/assets/b7106292-44f2-490b-80cb-c205572bb5a1" />
<img width="262" height="414" alt="Screenshot 2026-05-02 at 21 17 15" src="https://github.com/user-attachments/assets/07801bec-0922-47f9-ac5a-a0576e923b1a" />

* File Size: 753 KB
* Dimensions: 512 x 512
* Resolution: 72 x 72
* Color Space: RGB
* Color Profile: sRGB IEC61966-2.1
* Alpha Channel: No
* Created: March 27, 2023
* Modified: March 27, 2023
* Encoded Image: StegoNight.png

### File Name: StegoNight.png
<img width="512" height="512" alt="StegoNight" src="https://github.com/user-attachments/assets/7f932ed0-e1c9-423d-8686-bd40be4c7f25" />
<img width="266" height="387" alt="Screenshot 2026-05-02 at 21 18 13" src="https://github.com/user-attachments/assets/e238758b-7e3a-4d12-b79a-a0747799e14c" />
<img width="426" height="731" alt="Screenshot 2026-05-02 at 21 17 40" src="https://github.com/user-attachments/assets/008f3ff1-c334-4c31-af63-bc94ad6a4afe" />

* File Size: 611 KB
* Dimensions: 512 x 512
* Color Space: RGB
* Alpha Channel: Yes
* Created: May 2, 2026
* Modified: May 2, 2026

## Key Observations:
* The image looks visually identical to the original.
* The hidden message is stored in the least significant bits of RGB values.
* The encoded file introduces an alpha channel, even if the original did not have one.
* File size may change due to:
  * Pixel data rewriting
  * PNG compression differences
* No visible artifacts are introduced to the human eye.

## What Changed Under the Hood:
* RGB values were slightly modified at the binary level.
* Each pixel stores 3 bits of encrypted data.
* The embedded payload includes:
  * Message length
  * Magic header
  * Salt
  * Encrypted message
  * Security Insight

### Even if someone...
* Extracts raw pixel data
* Detects LSB manipulation

### ... They still cannot read the message without:
* The correct password
* The derived encryption key

## Important Notes:
* Use PNG files only.
* Avoid JPEG, JPG, or compressed image formats because compression can destroy the hidden data.
* Do not resize, compress, crop, or edit the encoded image after hiding a message.

## Limitations:
* This project is designed for learning and portfolio demonstration.
* It **IS NOT** intended for protecting classified, regulated, or highly sensitive information.
* LSB steganography can be detected using steganalysis tools if someone suspects hidden data exists.
