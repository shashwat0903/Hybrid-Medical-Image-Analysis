import os
import io
import json
import pickle
import base64
import hashlib
import secrets
import random
import logging
import lzma

from flask import Flask, request, render_template, flash, redirect, url_for
from PIL import Image
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

# ── Setup ────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "replace_with_secure_random")

# ── Helpers ─────────────────────────────────────────────────────────────
def compute_sha256(data_bytes):
    return hashlib.sha256(data_bytes).hexdigest()

def remove_duplicate_rows_and_cols(arr):
    unique_rows, seen = [], set()
    for row in arr:
        t = tuple(row.tolist())
        if t not in seen:
            seen.add(t)
            unique_rows.append(row)
    arr2 = np.stack(unique_rows, 0)
    unique_cols, seen = [], set()
    for j in range(arr2.shape[1]):
        col = arr2[:, j]
        t = tuple(col.tolist())
        if t not in seen:
            seen.add(t)
            unique_cols.append(col)
    return np.stack(unique_cols, 1)

def rle_encode_row(row):
    if len(row) == 0:
        return []
    out, curr, cnt = [], int(row[0]), 1
    for p in row[1:]:
        p = int(p)
        if p == curr and cnt < 255:
            cnt += 1
        else:
            out.append((curr, cnt))
            curr, cnt = p, 1
    out.append((curr, cnt))
    return out

def rle_encode_image(arr):
    return [rle_encode_row(arr[i]) for i in range(arr.shape[0])]

def merge_pixels(img, ratio):
    w = max(1, int(round(img.width * ratio)))
    h = max(1, int(round(img.height * ratio)))
    return np.array(img.resize((w, h), Image.LANCZOS))

alpha, beta = 1.4, 0.3
def henon_map_sequence(n, x0=0.1, y0=0.3):
    seq, x, y = [], x0, y0
    for _ in range(n):
        x, y = 1 - alpha*x*x + y, beta*x
        seq.append(int(abs(x*1000) % 256))
    return seq

def row_col_shift(arr):
    out = arr.copy()
    r, c = arr.shape
    for i, s in enumerate(henon_map_sequence(r)):
        out[i] = np.roll(out[i], s % c)
    for j, s in enumerate(henon_map_sequence(c)):
        out[:, j] = np.roll(out[:, j], s % r)
    return out

def inverse_row_col_shift(arr):
    out = arr.copy()
    r, c = arr.shape
    for j, s in enumerate(henon_map_sequence(c)):
        out[:, j] = np.roll(out[:, j], -s % r)
    for i, s in enumerate(henon_map_sequence(r)):
        out[i] = np.roll(out[i], -s % c)
    return out

# ECC (secp256k1)
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a, b = 0, 7
Gx, Gy = (
    55066263022277343669578718895168534326250603453777594175500187360389116729240,
    32670510020758816978083085130507043184471273380659243275938904335757337482424
)

def mod_inv(x, m):
    return pow(x, m-2, m)

def ecc_add(P, Q):
    if P == (None, None):
        return Q
    if Q == (None, None):
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 != y2 or y1 == 0):
        return (None, None)
    if P == Q:
        s = (3*x1*x1 + a)*mod_inv(2*y1, p) % p
    else:
        s = (y2-y1)*mod_inv((x2-x1) % p, p) % p
    x3 = (s*s - x1 - x2) % p
    y3 = (s*(x1-x3) - y1) % p
    return (x3, y3)

def ecc_mul(k, P):
    R, Q = (None, None), P
    while k:
        if k & 1:
            R = ecc_add(R, Q)
        Q = ecc_add(Q, Q)
        k //= 2
    return R

def encrypt_image_pixels(data_bytes, h, w):
    eph = secrets.randbelow(p-1) + 1
    kG  = ecc_mul(eph, (Gx, Gy))
    random.seed(kG[1] or 0)
    xored = bytearray(b ^ random.getrandbits(8) for b in data_bytes)
    arr = np.frombuffer(xored, dtype=np.uint8).reshape((h, w))
    return row_col_shift(arr), kG

def decrypt_image_pixels(arr, kG):
    unsh = inverse_row_col_shift(arr)
    random.seed(kG[1] or 0)
    flat = unsh.flatten()
    plain = bytearray(b ^ random.getrandbits(8) for b in flat)
    return np.frombuffer(plain, dtype=np.uint8).reshape(unsh.shape)

# Chart helpers
def plot_histogram(arr, title):
    fig, ax = plt.subplots(figsize=(4,3))
    ax.hist(arr.flatten(), bins=256)
    ax.set_title(title)
    ax.set_xlabel('Pixel')
    ax.set_ylabel('Freq')
    buf = io.BytesIO()
    fig.tight_layout()
    fig.savefig(buf, format='png', bbox_inches='tight')
    buf.seek(0)
    plt.close(fig)
    return base64.b64encode(buf.getvalue()).decode()

def plot_bar(vals, labels, title):
    fig, ax = plt.subplots(figsize=(4,3))
    ax.bar(labels, vals)
    ax.set_title(title)
    ax.set_ylabel('Bytes')
    buf = io.BytesIO()
    fig.tight_layout()
    fig.savefig(buf, format='png', bbox_inches='tight')
    buf.seek(0)
    plt.close(fig)
    return base64.b64encode(buf.getvalue()).decode()

# ── Routes ──────────────────────────────────────────────────────────────

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    f     = request.files.get('image_file')
    ratio = request.form.get('compression_ratio', type=float)
    if not f or ratio is None:
        flash("Upload image & ratio", "warning")
        return redirect(url_for('index'))

    # 1) Raw
    img        = Image.open(f).convert('L')
    orig       = np.array(img)
    orig_bytes = orig.tobytes()
    orig_size  = len(orig_bytes)
    orig_px    = orig.size

    # 2) Dedup + RLE + LZMA
    dedup      = remove_duplicate_rows_and_cols(orig)
    rle_rows   = rle_encode_image(dedup)
    rle_bytes  = pickle.dumps(rle_rows)
    rle_size   = len(rle_bytes)
    lzma_bytes = lzma.compress(rle_bytes)
    lzma_size  = len(lzma_bytes)

    # 3) Merge
    merged      = merge_pixels(img, ratio)
    merged      = remove_duplicate_rows_and_cols(merged)
    merged_px   = merged.size
    comp_bytes  = merged.tobytes()
    comp_size   = len(comp_bytes)
    comp_hash   = compute_sha256(comp_bytes)

    # 4) Encrypt
    cipher_arr, kG = encrypt_image_pixels(comp_bytes, merged.shape[0], merged.shape[1])

    # 5) Charts & hist
    hist_orig   = plot_histogram(orig,    'Original Histogram')
    hist_comp   = plot_histogram(merged,  'Compressed Histogram')
    hist_cipher = plot_histogram(cipher_arr,'Cipher Histogram')
    chart_rle   = plot_bar([orig_size, rle_size], ['Raw','RLE'], 'Raw vs RLE')
    chart_lzma  = plot_bar([orig_size, lzma_size], ['Raw','LZMA'], 'Raw vs LZMA')
    chart_merge = plot_bar([orig_size, comp_size], ['Raw','Merged'], 'Raw vs Merged')

    # 6) to_base64
    def to_b64(a):
        bio = io.BytesIO()
        Image.fromarray(a, 'L').save(bio, 'PNG')
        return base64.b64encode(bio.getvalue()).decode()

    orig_b64   = to_b64(orig)
    comp_b64   = to_b64(merged)
    cipher_b64 = to_b64(cipher_arr)

    # 7) ECC JSON + params
    ecc_json = {
        "curve_name": "secp256k1",
        "p": hex(p),
        "a": a,
        "b": b,
        "G": {"x": str(Gx), "y": str(Gy)},
        "ephemeral_kG": {"x": str(kG[0]), "y": str(kG[1])},
        "compressed_sha256": comp_hash
    }
    ecc_b64 = base64.b64encode(json.dumps(ecc_json).encode()).decode()

    # 8) Pixel reduction
    red_px  = orig_px - merged_px
    red_pct = round(100 * red_px / orig_px, 2)

    return render_template('index.html',
        show_encrypt=True,
        # images & charts
        original_image_b64=orig_b64,
        compressed_image_b64=comp_b64,
        cipher_image_b64=cipher_b64,
        hist_orig_b64=hist_orig,
        hist_comp_b64=hist_comp,
        hist_cipher_b64=hist_cipher,
        chart_rle_b64=chart_rle,
        chart_lzma_b64=chart_lzma,
        chart_merge_b64=chart_merge,
        # sizes & pixels & hash
        orig_size=orig_size, rle_size=rle_size, lzma_size=lzma_size, comp_size=comp_size,
        orig_px=orig_px, dedup_px=dedup.size, merged_px=merged_px,
        red_px=red_px, red_pct=red_pct,
        # ECC
        ecc_params=ecc_json,
        ecc_data_b64=ecc_b64
    )

@app.route('/decrypt', methods=['POST'])
def decrypt():
    f_img = request.files.get('cipher_file')
    f_ecc = request.files.get('ecc_file')
    if not f_img or not f_ecc:
        flash("Upload cipher & ECC JSON", "warning")
        return redirect(url_for('index'))

    data        = json.load(f_ecc)
    comp_hash   = data.get("compressed_sha256")
    kG          = (int(data["ephemeral_kG"]["x"]), int(data["ephemeral_kG"]["y"]))
    arr         = np.array(Image.open(f_img).convert('L'))
    plain       = decrypt_image_pixels(arr, kG)
    plain_bytes = plain.tobytes()
    decrypted_hash = compute_sha256(plain_bytes)

    buf = io.BytesIO()
    Image.fromarray(plain, 'L').save(buf, 'PNG')
    decrypted_b64 = base64.b64encode(buf.getvalue()).decode()

    match = (decrypted_hash == comp_hash)

    return render_template('index.html',
        show_decrypt=True,
        decrypted_image_b64=decrypted_b64,
        comp_hash=comp_hash,
        decrypted_hash=decrypted_hash,
        hash_match=match
    )

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
