import os
import io
import base64
import json
import pickle
import hashlib
import secrets
import random
import logging
from flask import Flask, request, render_template
from PIL import Image, ImageDraw, ImageFont
import numpy as np
import matplotlib
matplotlib.use('Agg')  # for headless environments
import matplotlib.pyplot as plt

# Set up logging for debugging
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
app.secret_key = 'replace_with_a_secure_random_secret'

########################################################################
# Pre‑processing Helpers
########################################################################

def remove_duplicate_rows_and_cols(arr):
    """
    Remove rows and columns with identical pixel values from a 2D numpy array.
    Only the first occurrence of each unique row/column is kept.
    """
    # Remove duplicate rows using tuple conversion.
    unique_rows = []
    seen_rows = set()
    for row in arr:
        row_tuple = tuple(row.tolist())
        if row_tuple not in seen_rows:
            seen_rows.add(row_tuple)
            unique_rows.append(row)
    new_arr = np.stack(unique_rows, axis=0)

    # Remove duplicate columns.
    unique_cols = []
    seen_cols = set()
    for j in range(new_arr.shape[1]):
        col = new_arr[:, j]
        col_tuple = tuple(col.tolist())
        if col_tuple not in seen_cols:
            seen_cols.add(col_tuple)
            unique_cols.append(col)
    final_arr = np.stack(unique_cols, axis=1)
    return final_arr

def rle_encode_row(row):
    """
    Perform run-length encoding on a single row.
    """
    if len(row) == 0:
        return []
    encoded = []
    current = int(row[0])
    count = 1
    for pixel in row[1:]:
        if int(pixel) == current and count < 255:
            count += 1
        else:
            encoded.append((current, count))
            current = int(pixel)
            count = 1
    encoded.append((current, count))
    return encoded

def rle_encode_image(arr):
    """
    Apply RLE encoding row-wise to a 2D numpy array.
    """
    encoded_rows = []
    for i in range(arr.shape[0]):
        encoded_rows.append(rle_encode_row(arr[i, :]))
    return encoded_rows

def rle_decode_image(encoded_rows, width):
    """
    Decode a run-length encoded image row-wise.
    """
    decoded_rows = []
    for runs in encoded_rows:
        row = []
        for (val, count) in runs:
            row.extend([val] * count)
        if len(row) != width:
            row = row[:width] + [row[-1]] * (width - len(row))
        decoded_rows.append(row)
    return np.array(decoded_rows, dtype=np.uint8)

########################################################################
# Compression (Block Merging)
########################################################################

def merge_pixels(image, ratio):
    """
    Downsample an image using Pillow's resize with LANCZOS resampling.
    The new dimensions are:
      new_width = round(original_width * ratio)
      new_height = round(original_height * ratio)
    """
    new_width = max(1, int(round(image.width * ratio)))
    new_height = max(1, int(round(image.height * ratio)))
    new_img = image.resize((new_width, new_height), resample=Image.LANCZOS)
    return np.array(new_img)

########################################################################
# Henon Map–Based Row/Column Shift Encryption/Decryption
########################################################################

# Henon Map parameters
alpha = 1.4
beta = 0.3

def henon_map_sequence(size, x0=0.1, y0=0.3):
    """
    Generate a Henon map sequence of integer shift values.
    """
    seq = []
    x, y = x0, y0
    for _ in range(size):
        x = 1 - alpha * x * x + y
        y = beta * x
        seq.append(int(abs(x * 1000) % 256))
    return seq

def row_col_shift(arr):
    """
    Apply a shift on rows and columns of a 2D array based on the Henon map sequence.
    """
    rows, cols = arr.shape
    row_shifts = henon_map_sequence(rows)
    col_shifts = henon_map_sequence(cols)
    shifted = np.copy(arr)
    # Shift rows by the corresponding shift amount.
    for i in range(rows):
        shifted[i, :] = np.roll(shifted[i, :], row_shifts[i] % cols)
    # Shift columns by the corresponding shift amount.
    for j in range(cols):
        shifted[:, j] = np.roll(shifted[:, j], col_shifts[j] % rows)
    return shifted

def inverse_row_col_shift(arr):
    """
    Reverse the Henon map–based row and column shifts.
    """
    rows, cols = arr.shape
    row_shifts = henon_map_sequence(rows)
    col_shifts = henon_map_sequence(cols)
    unshifted = np.copy(arr)
    # Reverse column shifts first.
    for j in range(cols):
        unshifted[:, j] = np.roll(unshifted[:, j], - (col_shifts[j] % rows))
    # Then reverse row shifts.
    for i in range(rows):
        unshifted[i, :] = np.roll(unshifted[i, :], - (row_shifts[i] % cols))
    return unshifted

########################################################################
# SHA-256 Hash Computation
########################################################################

def compute_sha256(data_bytes):
    """
    Compute the SHA-256 hash of the input bytes.
    """
    return hashlib.sha256(data_bytes).hexdigest()

########################################################################
# ECC Helpers – Using secp256k1 Parameters
########################################################################

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a = 0
b = 7
G = (
    55066263022277343669578718895168534326250603453777594175500187360389116729240,
    32670510020758816978083085130507043184471273380659243275938904335757337482424
)
curve_name = "secp256k1"

def mod_inv(k, p):
    """
    Compute the modular inverse of k modulo p.
    """
    return pow(k, p-2, p)

def ecc_add(P, Q):
    """
    Add two points on the secp256k1 elliptic curve.
    """
    if P == (None, None):
        return Q
    if Q == (None, None):
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 != y2 or y1 == 0):
        return (None, None)
    if P == Q:
        s = (3 * x1 * x1 + a) * mod_inv(2 * y1, p) % p
    else:
        s = (y2 - y1) * mod_inv((x2 - x1) % p, p) % p
    x3 = (s * s - x1 - x2) % p
    y3 = (s * (x1 - x3) - y1) % p
    return (x3, y3)

def ecc_mul(k, P):
    """
    Multiply a point on the elliptic curve by a scalar.
    """
    result = (None, None)
    addend = P
    while k:
        if k & 1:
            result = ecc_add(result, addend)
        addend = ecc_add(addend, addend)
        k //= 2
    return result

########################################################################
# ECC-Based Pixelwise Encryption & Decryption (Using Henon Map Only)
########################################################################

def encrypt_image_pixels(image_bytes, height, width):
    """
    Encrypt image pixels using:
      1. An ECC-derived random XOR key stream.
      2. A Henon map–based row/column shift.
    Returns the cipher image (2D numpy array) and ECC point kG.
    """
    # Generate ECC ephemeral key and derive seed.
    ephemeral_k = secrets.randbelow(p - 1) + 1
    kG = ecc_mul(ephemeral_k, G)
    seed_val = kG[1] if kG[1] is not None else 9999
    random.seed(seed_val)
    # XOR encryption.
    xored = bytearray()
    for b in image_bytes:
        rnd = random.getrandbits(8)
        xored.append(b ^ rnd)
    encrypted_arr = np.frombuffer(xored, dtype=np.uint8).reshape((height, width))
    # Apply Henon map-based row/column shifts.
    cipher_arr = row_col_shift(encrypted_arr)
    return cipher_arr, kG

def decrypt_image_pixels(cipher_arr, kG, height, width):
    """
    Decrypt the cipher image by reversing the Henon map row/column shifts 
    and then XORing with the same keystream.
    """
    # Reverse the Henon map-based shifts.
    unshifted_arr = inverse_row_col_shift(cipher_arr)
    seed_val = kG[1] if kG[1] is not None else 9999
    random.seed(seed_val)
    # Reverse the XOR encryption.
    xored = bytearray()
    flat_data = unshifted_arr.flatten()
    for b in flat_data:
        rnd = random.getrandbits(8)
        xored.append(b ^ rnd)
    plain_arr = np.frombuffer(xored, dtype=np.uint8).reshape((height, width))
    return plain_arr

########################################################################
# Flask Route: Compression, Encryption, Decryption, and Hash Comparison
########################################################################

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files.get('image_file')
        comp_ratio_str = request.form.get('compression_ratio', '')
        if not file:
            return "No file uploaded.", 400
        try:
            orig_img = Image.open(file).convert('L')
        except Exception:
            return "Error opening image.", 400

        # Process Original Image
        orig_width, orig_height = orig_img.size
        orig_arr = np.array(orig_img)
        orig_bytes = orig_arr.tobytes()
        orig_size = len(orig_bytes)
        orig_hash = compute_sha256(orig_bytes)

        # Preprocessing: Remove duplicate rows/cols before RLE encoding.
        dedup_arr = remove_duplicate_rows_and_cols(orig_arr)
        encoded_rows = rle_encode_image(dedup_arr)
        rle_serialized = pickle.dumps(encoded_rows)
        rle_size = len(rle_serialized)

        # Compression: Downsample via block merging and then remove duplicate rows/cols.
        try:
            ratio = float(comp_ratio_str)
            if not (0 < ratio <= 1):
                ratio = 1.0
        except ValueError:
            ratio = 1.0
        merged_arr = merge_pixels(orig_img, ratio)
        merged_dedup_arr = remove_duplicate_rows_and_cols(merged_arr)
        comp_img = Image.fromarray(merged_dedup_arr, mode='L')
        comp_bytes = merged_dedup_arr.tobytes()
        comp_size = len(comp_bytes)
        comp_hash = compute_sha256(comp_bytes)

        # Create Hash Comparison Indicator
        if orig_hash != comp_hash:
            indicator = Image.new('L', (100, 100), color=0)  # Black background
            draw = ImageDraw.Draw(indicator)
            font = ImageFont.load_default()
            text = "DIFF"
            bbox = draw.textbbox((0, 0), text, font=font)
            x = (100 - (bbox[2] - bbox[0])) / 2
            y = (100 - (bbox[3] - bbox[1])) / 2
            draw.text((x, y), text, font=font, fill=255)
            hash_match_text = "Hashes Differ"
        else:
            indicator = Image.new('L', (100, 100), color=255)  # White background
            draw = ImageDraw.Draw(indicator)
            font = ImageFont.load_default()
            text = "MATCH"
            bbox = draw.textbbox((0, 0), text, font=font)
            x = (100 - (bbox[2] - bbox[0])) / 2
            y = (100 - (bbox[3] - bbox[1])) / 2
            draw.text((x, y), text, font=font, fill=0)
            hash_match_text = "Hashes Match"
        buf_ind = io.BytesIO()
        indicator.save(buf_ind, format='PNG')
        buf_ind.seek(0)
        hash_indicator_b64 = base64.b64encode(buf_ind.read()).decode('utf-8')

        # Size Comparison Chart
        fig, ax = plt.subplots(figsize=(6, 4))
        labels = ['Original Raw', 'RLE Serialized', 'Merged (Compressed)']
        sizes = [orig_size, rle_size, comp_size]
        ax.bar(labels, sizes, color=['blue', 'orange', 'green'])
        ax.set_ylabel('Size (bytes)')
        ax.set_title('Size Comparison')
        buf_chart = io.BytesIO()
        plt.savefig(buf_chart, format='png', bbox_inches='tight')
        buf_chart.seek(0)
        chart_b64 = base64.b64encode(buf_chart.read()).decode('utf-8')
        plt.close(fig)

        # ECC-Based Encryption (Using Henon Map only)
        cipher_arr, kG = encrypt_image_pixels(comp_bytes, comp_img.height, comp_img.width)
        cipher_img = Image.fromarray(cipher_arr, mode='L')

        # Demonstration: Decrypt the cipher image to recover the original compressed image.
        decrypted_arr = decrypt_image_pixels(cipher_arr, kG, comp_img.height, comp_img.width)
        decrypted_img = Image.fromarray(decrypted_arr, mode='L')

        # Prepare ECC Data for Display
        ecc_data = {
            "curve_name": curve_name,
            "p": hex(p),
            "a": a,
            "b": b,
            "G": {"x": str(G[0]), "y": str(G[1])},
            "ephemeral_kG": {"x": str(kG[0]), "y": str(kG[1])}
        }
        ecc_data_str = json.dumps(ecc_data, indent=4)
        ecc_data_b64 = base64.b64encode(ecc_data_str.encode('utf-8')).decode('utf-8')

        # Convert images to Base64 for Display
        def img_to_b64(img):
            buf = io.BytesIO()
            img.save(buf, format='PNG')
            buf.seek(0)
            return base64.b64encode(buf.read()).decode('utf-8')

        orig_img_b64 = img_to_b64(orig_img)
        comp_img_b64 = img_to_b64(comp_img)
        cipher_img_b64 = img_to_b64(cipher_img)
        decrypted_img_b64 = img_to_b64(decrypted_img)

        ecc_info_display = (
            f"<strong>ECC Curve:</strong> {curve_name}<br>"
            f"<strong>p:</strong> {hex(p)}<br>"
            f"<strong>a:</strong> {a}<br>"
            f"<strong>b:</strong> {b}<br>"
            f"<strong>Base Point G:</strong> ({G[0]}, {G[1]})<br>"
            f"<strong>Ephemeral Encryption Point kG:</strong> ({kG[0]}, {kG[1]})"
        )

        return render_template('index.html',
                               original_image_b64=orig_img_b64,
                               compressed_image_b64=comp_img_b64,
                               cipher_image_b64=cipher_img_b64,
                               decrypted_image_b64=decrypted_img_b64,
                               chart_base64=chart_b64,
                               hash_indicator_b64=hash_indicator_b64,
                               hash_match_text=hash_match_text,
                               orig_size=orig_size,
                               rle_size=rle_size,
                               comp_size=comp_size,
                               orig_hash=orig_hash,
                               comp_hash=comp_hash,
                               ecc_info=ecc_info_display,
                               ecc_data_b64=ecc_data_b64,
                               comp_ratio_input=ratio)
    else:
        return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
