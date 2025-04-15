import json
import random
import io
from PIL import Image
import numpy as np

def zigzag_indices(n_rows, n_cols):
    """Generate zigzag order indices for a 2D array of shape (n_rows, n_cols)."""
    indices = []
    for s in range(n_rows + n_cols - 1):
        if s % 2 == 0:
            for i in range(min(s, n_rows - 1), -1, -1):
                j = s - i
                if j < n_cols:
                    indices.append((i, j))
        else:
            for i in range(max(0, s - n_cols + 1), min(s + 1, n_rows)):
                j = s - i
                if j < n_cols:
                    indices.append((i, j))
    return indices

def inverse_zigzag(matrix):
    """
    Compute the inverse of the zigzag permutation.
    Given an image (2D NumPy array) that was rearranged via a zigzag ordering,
    this function returns the array rearranged back into its original order.
    """
    n_rows, n_cols = matrix.shape
    indices = zigzag_indices(n_rows, n_cols)
    flat = matrix.flatten()
    out = np.empty_like(flat)
    # For each new index, place the value back to its original index.
    for new_idx, (i, j) in enumerate(indices):
        original_index = i * n_cols + j
        out[original_index] = flat[new_idx]
    return out.reshape(n_rows, n_cols)

def main():
    # Load ECC data (the JSON file produced during encryption)
    with open("ecc_data.json", "r") as f:
        ecc_data = json.load(f)
    # Extract the ephemeral encryption point kG from the ECC data.
    # (kG is stored as strings; convert them to integers.)
    kG = (int(ecc_data["ephemeral_kG"]["x"]), int(ecc_data["ephemeral_kG"]["y"]))
    # Use the y-coordinate of kG to seed the random generator.
    seed_val = kG[1] if kG[1] is not None else 9999
    random.seed(seed_val)

    # Open the cipher image (encrypted image) and convert to grayscale.
    cipher_img = Image.open("cipher_image.png").convert("L")
    width, height = cipher_img.size
    cipher_arr = np.array(cipher_img)

    # Inverse the zigzag permutation to recover the "xored" image.
    xored_arr = inverse_zigzag(cipher_arr)

    # Flatten the recovered array to get the xored bytes.
    xored_bytes = xored_arr.flatten()

    # Re-generate the same random byte stream (the length of the xored bytes).
    rand_bytes = bytearray()
    for _ in range(len(xored_bytes)):
        rand_bytes.append(random.getrandbits(8))
    
    # XOR the recovered xored bytes with the random byte stream to get the original merged bytes.
    merged_bytes = bytearray([b ^ r for b, r in zip(xored_bytes, rand_bytes)])
    
    # Reshape the bytes back to the image's dimensions.
    merged_arr = np.array(merged_bytes, dtype=np.uint8).reshape((height, width))
    decrypted_img = Image.fromarray(merged_arr, mode="L")
    
    # Save the decrypted (compressed) image.
    decrypted_img.save("decrypted.png")
    print("Decryption complete. Decrypted image saved as 'decrypted.png'.")

if __name__ == '__main__':
    main()
