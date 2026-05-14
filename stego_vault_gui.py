# stego_vault_gui.py

"""
StegoVault

Cross-platform PNG steganography tool for macOS and Windows.

Install:
python -m pip install pillow cryptography tkinterdnd2

Run on Mac:
python3 stego_vault_gui.py

Run on Windows:
python stego_vault_gui.py
"""

import base64
import os
import struct
import tkinter as tk

from pathlib import Path
from tkinter import filedialog, messagebox

from PIL import Image
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from tkinterdnd2 import DND_FILES, TkinterDnD


# =========================================================
# Constants
# =========================================================

MAGIC_HEADER = b"STEGOVAULT"
SALT_SIZE = 16
KEY_ITERATIONS = 390000
ESTIMATED_ENCRYPTION_OVERHEAD = 160


# =========================================================
# Path Helpers
# =========================================================

def normalize_png_output_path(path: str) -> str:
    """
    Ensures the output file path ends with .png.
    """
    output_path = Path(path)

    if output_path.suffix.lower() != ".png":
        output_path = output_path.with_suffix(".png")

    return str(output_path)


def validate_png_path(path: str, must_exist: bool = True) -> Path:
    """
    Validates that the selected path is a PNG file.
    """
    file_path = Path(path)

    if must_exist and not file_path.exists():
        raise ValueError("The selected file does not exist.")

    if file_path.suffix.lower() != ".png":
        raise ValueError("Only PNG files are supported.")

    return file_path


def clean_dropped_path(path: str) -> str:
    """
    Cleans drag and drop file paths.

    Some systems wrap dropped paths in braces.
    """
    cleaned_path = path.strip()

    if cleaned_path.startswith("{") and cleaned_path.endswith("}"):
        cleaned_path = cleaned_path[1:-1]

    return cleaned_path


# =========================================================
# Pillow Compatibility Helper
# =========================================================

def get_pixel_data(image):
    """
    Gets pixel data in a way that supports current and future Pillow versions.
    """
    if hasattr(image, "get_flattened_data"):
        return list(image.get_flattened_data())

    return list(image.getdata())


# =========================================================
# Capacity Helpers
# =========================================================

def calculate_image_capacity(input_path: str) -> int:
    """
    Estimates how many message bytes can fit inside the selected PNG image.
    """
    input_file = validate_png_path(input_path, must_exist=True)

    image = Image.open(input_file).convert("RGBA")
    pixels = get_pixel_data(image)

    total_bits = len(pixels) * 3
    total_bytes = total_bits // 8

    usable_bytes = max(0, total_bytes - ESTIMATED_ENCRYPTION_OVERHEAD)

    return usable_bytes


def estimate_message_size(message: str) -> int:
    """
    Estimates message size in UTF-8 bytes.
    """
    return len(message.encode("utf-8"))


# =========================================================
# Encryption Helpers
# =========================================================

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Creates a Fernet encryption key from a password and salt.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KEY_ITERATIONS,
    )

    return base64.urlsafe_b64encode(
        kdf.derive(password.encode("utf-8"))
    )


def encrypt_message(message: str, password: str) -> bytes:
    """
    Encrypts the message before embedding it into the image.
    """
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)

    encrypted_message = Fernet(key).encrypt(
        message.encode("utf-8")
    )

    payload = MAGIC_HEADER + salt + encrypted_message

    payload_length = struct.pack(">I", len(payload))

    return payload_length + payload


def decrypt_message(payload: bytes, password: str) -> str:
    """
    Decrypts the extracted hidden payload.
    """
    if not payload.startswith(MAGIC_HEADER):
        raise ValueError("No StegoVault hidden message was found.")

    salt_start = len(MAGIC_HEADER)
    salt_end = salt_start + SALT_SIZE

    salt = payload[salt_start:salt_end]
    encrypted_message = payload[salt_end:]

    key = derive_key(password, salt)

    try:
        decrypted_message = Fernet(key).decrypt(encrypted_message)
    except InvalidToken:
        raise ValueError("Incorrect password or corrupted hidden message.")

    return decrypted_message.decode("utf-8")


# =========================================================
# Bit Helpers
# =========================================================

def bytes_to_bits(data: bytes):
    """
    Converts bytes into individual bits.
    """
    for byte in data:
        for bit_index in range(7, -1, -1):
            yield (byte >> bit_index) & 1


def bits_to_bytes(bits):
    """
    Converts a list of bits back into bytes.
    """
    output = bytearray()

    for index in range(0, len(bits), 8):
        byte_bits = bits[index:index + 8]

        if len(byte_bits) < 8:
            break

        value = 0

        for bit in byte_bits:
            value = (value << 1) | bit

        output.append(value)

    return bytes(output)


# =========================================================
# Image Encoding and Decoding
# =========================================================

def encode_image(input_path: str, output_path: str, message: str, password: str):
    """
    Hides an encrypted message inside a PNG image using LSB steganography.
    """
    input_file = validate_png_path(input_path, must_exist=True)
    output_file = normalize_png_output_path(output_path)

    image = Image.open(input_file).convert("RGBA")
    pixels = get_pixel_data(image)

    payload = encrypt_message(message, password)
    payload_bits = list(bytes_to_bits(payload))

    available_bits = len(pixels) * 3

    if len(payload_bits) > available_bits:
        raise ValueError("The message is too large for this image.")

    new_pixels = []
    bit_index = 0

    for red, green, blue, alpha in pixels:
        if bit_index < len(payload_bits):
            red = (red & 0xFE) | payload_bits[bit_index]
            bit_index += 1

        if bit_index < len(payload_bits):
            green = (green & 0xFE) | payload_bits[bit_index]
            bit_index += 1

        if bit_index < len(payload_bits):
            blue = (blue & 0xFE) | payload_bits[bit_index]
            bit_index += 1

        new_pixels.append((red, green, blue, alpha))

    encoded_image = Image.new("RGBA", image.size)
    encoded_image.putdata(new_pixels)
    encoded_image.save(output_file, "PNG")


def decode_image(input_path: str, password: str) -> str:
    """
    Extracts and decrypts a hidden message from a PNG image.
    """
    input_file = validate_png_path(input_path, must_exist=True)

    image = Image.open(input_file).convert("RGBA")
    pixels = get_pixel_data(image)

    extracted_bits = []

    for red, green, blue, alpha in pixels:
        extracted_bits.append(red & 1)
        extracted_bits.append(green & 1)
        extracted_bits.append(blue & 1)

    length_bits = extracted_bits[:32]
    length_bytes = bits_to_bytes(length_bits)

    if len(length_bytes) != 4:
        raise ValueError("Could not read hidden message length.")

    payload_length = struct.unpack(">I", length_bytes)[0]
    payload_bit_length = payload_length * 8

    payload_bits = extracted_bits[32:32 + payload_bit_length]
    payload = bits_to_bytes(payload_bits)

    return decrypt_message(payload, password)


# =========================================================
# Scrollable Frame
# =========================================================

class ScrollableFrame(tk.Frame):
    """
    A vertically scrollable frame for better usability on smaller screens.
    """

    def __init__(self, parent):
        super().__init__(parent)

        self.canvas = tk.Canvas(self, borderwidth=0)
        self.scrollbar = tk.Scrollbar(
            self,
            orient="vertical",
            command=self.canvas.yview
        )

        self.scrollable_frame = tk.Frame(self.canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda event: self.canvas.configure(
                scrollregion=self.canvas.bbox("all")
            )
        )

        self.canvas_frame = self.canvas.create_window(
            (0, 0),
            window=self.scrollable_frame,
            anchor="nw"
        )

        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        self.canvas.bind("<Configure>", self._on_canvas_configure)

        self._bind_mousewheel()

    def _on_canvas_configure(self, event):
        """
        Makes the inner frame match the canvas width.
        """
        self.canvas.itemconfig(self.canvas_frame, width=event.width)

    def _bind_mousewheel(self):
        """
        Adds mouse wheel support for macOS and Windows.
        """
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind_all("<Button-4>", self._on_mousewheel)
        self.canvas.bind_all("<Button-5>", self._on_mousewheel)

    def _on_mousewheel(self, event):
        """
        Handles mouse wheel scrolling.
        """
        if event.num == 5 or event.delta < 0:
            self.canvas.yview_scroll(1, "units")
        elif event.num == 4 or event.delta > 0:
            self.canvas.yview_scroll(-1, "units")


# =========================================================
# GUI Application
# =========================================================

class StegoVaultGUI:
    """
    GUI application for hiding and extracting encrypted messages in PNG files.
    """

    def __init__(self, root):
        self.root = root
        self.root.title("StegoVault")
        self.root.geometry("760x700")
        self.root.minsize(620, 520)
        self.root.resizable(True, True)

        self.input_encode_path = tk.StringVar()
        self.output_encode_path = tk.StringVar()
        self.input_decode_path = tk.StringVar()

        self.build_gui()

    def build_gui(self):
        """
        Builds the main scrollable interface.
        """
        container = ScrollableFrame(self.root)
        container.pack(fill="both", expand=True, padx=12, pady=12)

        main_frame = container.scrollable_frame

        self.build_encode_section(main_frame)
        self.build_decode_section(main_frame)

    def build_encode_section(self, parent):
        """
        Builds the encode section.
        """
        encode_frame = tk.LabelFrame(parent, text="Hide Secret Message")
        encode_frame.pack(fill="both", expand=True, pady=8)

        tk.Label(encode_frame, text="Input PNG Image").pack(anchor="w", padx=8, pady=(8, 0))

        tk.Entry(
            encode_frame,
            textvariable=self.input_encode_path,
            width=90
        ).pack(anchor="w", padx=8)

        tk.Button(
            encode_frame,
            text="Browse",
            command=self.browse_encode_input
        ).pack(anchor="w", padx=8, pady=4)

        tk.Label(encode_frame, text="Secret Message").pack(anchor="w", padx=8, pady=(8, 0))

        self.message_box = tk.Text(encode_frame, height=6, width=90)
        self.message_box.pack(anchor="w", padx=8)
        self.message_box.bind("<KeyRelease>", lambda event: self.update_capacity_label())

        self.capacity_label = tk.Label(
            encode_frame,
            text="Capacity: Select a PNG image to preview capacity."
        )
        self.capacity_label.pack(anchor="w", padx=8, pady=(8, 0))

        self.capacity_help_label = tk.Label(
            encode_frame,
            text=(
                "Tips:\n"
                " • Larger PNG images can hide larger messages.\n"
                " • Use short text for small images.\n"
                " • Avoid JPEG because compression can destroy hidden data."
            ),
            wraplength=680,
            justify="left"
        )
        self.capacity_help_label.pack(anchor="w", padx=8, pady=(2, 4))

        tk.Button(
            encode_frame,
            text="Check Capacity",
            command=self.update_capacity_label
        ).pack(anchor="w", padx=8, pady=4)

        tk.Label(encode_frame, text="Password").pack(anchor="w", padx=8, pady=(8, 0))

        self.encode_password_entry = tk.Entry(
            encode_frame,
            show="*",
            width=40
        )
        self.encode_password_entry.pack(anchor="w", padx=8)

        tk.Label(encode_frame, text="Confirm Password").pack(anchor="w", padx=8, pady=(8, 0))

        self.confirm_password_entry = tk.Entry(
            encode_frame,
            show="*",
            width=40
        )
        self.confirm_password_entry.pack(anchor="w", padx=8)

        tk.Label(encode_frame, text="Output PNG Image").pack(anchor="w", padx=8, pady=(8, 0))

        tk.Entry(
            encode_frame,
            textvariable=self.output_encode_path,
            width=90
        ).pack(anchor="w", padx=8)

        tk.Button(
            encode_frame,
            text="Save As",
            command=self.browse_encode_output
        ).pack(anchor="w", padx=8, pady=4)

        tk.Button(
            encode_frame,
            text="Hide Message",
            command=self.hide_message,
            height=2,
            width=24
        ).pack(anchor="w", padx=8, pady=10)


    def build_decode_section(self, parent):
        """
        Builds the decode section.
        """
        decode_frame = tk.LabelFrame(parent, text="Extract Secret Message")
        decode_frame.pack(fill="both", expand=True, pady=8)

        tk.Label(
            decode_frame,
            text="Encoded PNG Image, browse or drag and drop"
        ).pack(anchor="w", padx=8, pady=(8, 0))

        self.decode_drop_entry = tk.Entry(
            decode_frame,
            textvariable=self.input_decode_path,
            width=90
        )
        self.decode_drop_entry.pack(anchor="w", padx=8)

        self.decode_drop_entry.drop_target_register(DND_FILES)
        self.decode_drop_entry.dnd_bind("<<Drop>>", self.handle_decode_drop)

        tk.Button(
            decode_frame,
            text="Browse",
            command=self.browse_decode_input
        ).pack(anchor="w", padx=8, pady=4)

        tk.Label(decode_frame, text="Password").pack(anchor="w", padx=8, pady=(8, 0))

        self.decode_password_entry = tk.Entry(
            decode_frame,
            show="*",
            width=40
        )
        self.decode_password_entry.pack(anchor="w", padx=8)

        tk.Button(
            decode_frame,
            text="Extract Message",
            command=self.extract_message,
            height=2,
            width=24
        ).pack(anchor="w", padx=8, pady=10)

        tk.Label(decode_frame, text="Extracted Message").pack(anchor="w", padx=8)

        self.extracted_box = tk.Text(decode_frame, height=6, width=90)
        self.extracted_box.pack(anchor="w", padx=8, pady=(0, 8))

        tk.Button(
            decode_frame,
            text="Copy to Clipboard",
            command=self.copy_to_clipboard
        ).pack(anchor="w", padx=8, pady=4)

    def browse_encode_input(self):
        """
        Opens a file picker for the source PNG image.
        """
        path = filedialog.askopenfilename(
            title="Select Input PNG Image",
            filetypes=[("PNG Images", "*.png")]
        )

        if path:
            self.input_encode_path.set(path)
            self.update_capacity_label()

    def browse_encode_output(self):
        """
        Opens a save dialog for the encoded PNG image.
        """
        path = filedialog.asksaveasfilename(
            title="Save Encoded PNG Image",
            defaultextension=".png",
            filetypes=[("PNG Images", "*.png")]
        )

        if path:
            self.output_encode_path.set(path)

    def browse_decode_input(self):
        """
        Opens a file picker for the encoded PNG image.
        """
        path = filedialog.askopenfilename(
            title="Select Encoded PNG Image",
            filetypes=[("PNG Images", "*.png")]
        )

        if path:
            self.input_decode_path.set(path)

    def handle_decode_drop(self, event):
        """
        Handles drag and drop for the decode image field.
        """
        dropped_path = clean_dropped_path(event.data)

        try:
            validate_png_path(dropped_path, must_exist=True)
            self.input_decode_path.set(dropped_path)
        except Exception as error:
            messagebox.showerror("Invalid File", str(error))

    def update_capacity_label(self):
        """
        Updates the capacity preview for the selected image and typed message.
        """
        input_path = self.input_encode_path.get()
        message = self.message_box.get("1.0", tk.END).strip()

        if not input_path:
            self.capacity_label.config(
                text="Capacity: Select a PNG image to preview capacity."
            )
            return

        try:
            capacity = calculate_image_capacity(input_path)
            message_size = estimate_message_size(message)
            remaining = capacity - message_size

            if remaining < 0:
                self.capacity_label.config(
                    text=(
                        f"Capacity: about {capacity} bytes available, "
                        f"message uses {message_size} bytes, "
                        f"over by {abs(remaining)} bytes."
                    )
                )
            else:
                self.capacity_label.config(
                    text=(
                        f"Capacity: about {capacity} bytes available, "
                        f"message uses {message_size} bytes, "
                        f"{remaining} bytes remaining."
                    )
                )

        except Exception as error:
            self.capacity_label.config(text=f"Capacity: {error}")

    def hide_message(self):
        """
        Validates fields, checks capacity, confirms password, warns on overwrite,
        then hides the encrypted message.
        """
        input_path = self.input_encode_path.get()
        output_path = self.output_encode_path.get()
        message = self.message_box.get("1.0", tk.END).strip()
        password = self.encode_password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        if not input_path or not output_path or not message or not password or not confirm_password:
            messagebox.showerror(
                "Missing Information",
                "Please fill out all encode fields."
            )
            return

        if password != confirm_password:
            messagebox.showerror(
                "Password Mismatch",
                "Password and confirm password do not match."
            )
            return

        try:
            capacity = calculate_image_capacity(input_path)
            message_size = estimate_message_size(message)

            if message_size > capacity:
                messagebox.showerror(
                    "Message Too Large",
                    "The message is too large for this image. Use a larger PNG image or shorten the message."
                )
                return

            normalized_output_path = normalize_png_output_path(output_path)

            if Path(normalized_output_path).exists():
                overwrite = messagebox.askyesno(
                    "Overwrite Existing File",
                    "A file already exists at the selected output path. Do you want to overwrite it?"
                )

                if not overwrite:
                    return

            encode_image(input_path, normalized_output_path, message, password)
            self.update_capacity_label()

            messagebox.showinfo(
                "Success",
                "Secret message hidden successfully."
            )

        except Exception as error:
            messagebox.showerror("Error", str(error))

    def extract_message(self):
        """
        Extracts and decrypts the hidden message from the selected image.
        """
        input_path = self.input_decode_path.get()
        password = self.decode_password_entry.get()

        if not input_path or not password:
            messagebox.showerror(
                "Missing Information",
                "Please select an image and enter the password."
            )
            return

        try:
            message = decode_image(input_path, password)

            self.extracted_box.delete("1.0", tk.END)
            self.extracted_box.insert(tk.END, message)

        except Exception as error:
            messagebox.showerror("Error", str(error))

    def copy_to_clipboard(self):
        """
        Copies the extracted message to the system clipboard.
        """
        message = self.extracted_box.get("1.0", tk.END).strip()

        if not message:
            messagebox.showwarning(
                "Nothing to Copy",
                "There is no extracted message to copy."
            )
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(message)

        messagebox.showinfo("Copied", "Message copied to clipboard.")


# =========================================================
# App Entry Point
# =========================================================

if __name__ == "__main__":
    root = TkinterDnD.Tk()
    app = StegoVaultGUI(root)
    root.mainloop()
