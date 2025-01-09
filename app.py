from flask import Flask, render_template, request, jsonify, send_file
import os
from PIL import Image
import base64
import io
import json
import numpy as np
import time
import psutil
import tracemalloc
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create uploads directory if it doesn't exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Steganography Implementation
# Membuat tabel karakter (62 karakter)
CHAR_TABLE = {}
REVERSE_CHAR_TABLE = {}

# Inisialisasi tabel karakter
def init_char_table():
    # Angka 0-9 (index 0-9)
    for i in range(10):
        CHAR_TABLE[str(i)] = i
        REVERSE_CHAR_TABLE[i] = str(i)
    
    # Huruf kecil a-z (index 10-35)
    for i, char in enumerate(range(ord('a'), ord('z') + 1)):
        CHAR_TABLE[chr(char)] = i + 10
        REVERSE_CHAR_TABLE[i + 10] = chr(char)
    
    # Huruf besar A-Z (index 36-61)
    for i, char in enumerate(range(ord('A'), ord('Z') + 1)):
        CHAR_TABLE[chr(char)] = i + 36
        REVERSE_CHAR_TABLE[i + 36] = chr(char)

def encrypt_custom(text, key):
    """Mengenkripsi teks menggunakan metode custom"""
    result = ""
    for char in text:
        if char in CHAR_TABLE:
            # C = (P + K) mod 62
            p_val = CHAR_TABLE[char]
            c_val = (p_val + key) % 62
            result += REVERSE_CHAR_TABLE[c_val]
        else:
            result += char
    return result

def decrypt_custom(cipher_text, key):
    """Mendekripsi teks menggunakan metode custom"""
    result = ""
    for char in cipher_text:
        if char in CHAR_TABLE:
            # P = (C - K) mod 62
            c_val = CHAR_TABLE[char]
            p_val = (c_val - key) % 62
            result += REVERSE_CHAR_TABLE[p_val]
        else:
            result += char
    return result

def text_to_binary(text):
    """Mengkonversi teks ke binary"""
    binary = ''.join(format(ord(char), '08b') for char in text)
    return binary

def monitor_resources(func):
    """Decorator untuk memonitor penggunaan sumber daya"""
    def wrapper(*args, **kwargs):
        # Mulai monitoring memori
        tracemalloc.start()
        # Catat waktu mulai
        start_time = time.time()
        # Catat penggunaan CPU awal
        cpu_start = psutil.cpu_percent(interval=None)
        
        # Jalankan fungsi
        result = func(*args, **kwargs)
        
        # Hitung penggunaan CPU
        cpu_end = psutil.cpu_percent(interval=None)
        # Hitung waktu eksekusi
        execution_time = time.time() - start_time
        # Hitung penggunaan memori
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        # Tampilkan hasil monitoring
        print("\nHasil Monitoring Sumber Daya:")
        print(f"Waktu Eksekusi: {execution_time:.2f} detik")
        print(f"Penggunaan CPU: {cpu_end:.1f}%")
        print(f"Penggunaan RAM: {current / 10**6:.2f} MB")
        print(f"Puncak Penggunaan RAM: {peak / 10**6:.2f} MB")
        
        return result
    return wrapper

@monitor_resources
def encode_image(image_path, secret_text, key):
    """Menyisipkan pesan terenkripsi ke dalam gambar menggunakan LSB"""
    try:
        # Buka gambar
        img = Image.open(image_path)
        
        # Konversi ke RGB jika diperlukan
        if img.mode != 'RGB':
            print(f"Mengkonversi gambar dari mode {img.mode} ke RGB...")
            img = img.convert('RGB')
        
        # Konversi ke PNG untuk menghindari kompresi lossy
        if image_path.lower().endswith('.jpg') or image_path.lower().endswith('.jpeg'):
            image_path = image_path.rsplit('.', 1)[0] + '.png'
            img.save(image_path, 'PNG')
            print("Gambar dikonversi ke PNG untuk menghindari kehilangan data")
        
        # Konversi ke array numpy setelah memastikan mode RGB
        img_array = np.array(img)
        
        # Verifikasi shape array
        if len(img_array.shape) != 3 or img_array.shape[2] != 3:
            raise ValueError(f"Format gambar tidak valid. Shape array: {img_array.shape}")

        # Enkripsi pesan
        encrypted_text = encrypt_custom(secret_text, key)
        print(f"Pesan terenkripsi: {encrypted_text}")
        
        # Tambahkan key ke encrypted text dengan separator khusus
        encoded_text = f"{encrypted_text}|{key}|"
        
        # Konversi pesan ke binary
        binary_message = text_to_binary(encoded_text) + '1111111111111110'  # Delimiter
        
        if len(binary_message) > img_array.size:
            raise ValueError("Pesan terlalu panjang untuk gambar ini")

        # Sisipkan pesan ke dalam pixel gambar
        idx = 0
        for i in range(img_array.shape[0]):
            for j in range(img_array.shape[1]):
                for k in range(3):  # RGB channels
                    if idx < len(binary_message):
                        img_array[i, j, k] = (img_array[i, j, k] & 254) | int(binary_message[idx])
                        idx += 1

        # Simpan gambar hasil
        result_img = Image.fromarray(img_array)
        
        # Perbaikan path output
        base_name = os.path.basename(image_path)
        output_path = "encoded_" + base_name
        output_dir = os.path.dirname(image_path)
        if output_dir:
            output_path = os.path.join(output_dir, output_path)
            
        # Pastikan output selalu dalam format PNG
        if not output_path.lower().endswith('.png'):
            output_path = output_path.rsplit('.', 1)[0] + '.png'
            
        result_img.save(output_path, 'PNG')
        
        # Hitung dan tampilkan MSE dan PSNR
        mse, psnr = calculate_mse_psnr(image_path, output_path)
        print(f"\nHasil analisis kualitas gambar:")
        print(f"MSE: {mse:.6f}")
        print(f"PSNR: {psnr:.2f} dB")
        
        return output_path
        
    except Exception as e:
        # Tambahkan informasi debug
        print(f"Debug info - Image mode: {img.mode if 'img' in locals() else 'unknown'}")
        print(f"Debug info - Array shape: {img_array.shape if 'img_array' in locals() else 'unknown'}")
        raise Exception(f"Terjadi kesalahan saat encoding: {str(e)}")

@monitor_resources
def decode_image(image_path, input_key):
    """Mengekstrak dan mendekripsi pesan dari gambar"""
    try:
        # Buka gambar
        img = Image.open(image_path)
        img_array = np.array(img)

        # Ekstrak binary message
        binary_message = ""
        for i in range(img_array.shape[0]):
            for j in range(img_array.shape[1]):
                for k in range(3):
                    binary_message += str(img_array[i, j, k] & 1)
                    if binary_message.endswith('1111111111111110'):
                        # Temukan delimiter dan hentikan ekstraksi
                        binary_message = binary_message[:-16]
                        # Konversi binary ke teks
                        message = ""
                        for idx in range(0, len(binary_message), 8):
                            byte = binary_message[idx:idx+8]
                            message += chr(int(byte, 2))
                        
                        # Pisahkan pesan dan key
                        try:
                            encrypted_text, stored_key, _ = message.split('|')
                            stored_key = int(stored_key)
                            
                            # Dekripsi pesan dengan kunci yang dimasukkan
                            decrypted_message = decrypt_custom(encrypted_text, input_key)
                            
                            # Langsung return hasil dekripsi tanpa validasi kunci
                            return {
                                'status': 'success',
                                'message': decrypted_message,
                                'encrypted': encrypted_text
                            }
                            
                        except Exception as e:
                            print(f"Decoding error detail: {str(e)}")
                            return {
                                'status': 'error',
                                'message': 'Format pesan tidak valid!'
                            }
        return None
        
    except Exception as e:
        raise Exception(f"Terjadi kesalahan saat decoding: {str(e)}")

def calculate_mse_psnr(original_image, stego_image):
    """Menghitung MSE dan PSNR antara dua gambar"""
    try:
        # Buka kedua gambar
        img1 = Image.open(original_image)
        img2 = Image.open(stego_image)
        
        # Pastikan kedua gambar dalam mode RGB
        if img1.mode != 'RGB':
            img1 = img1.convert('RGB')
        if img2.mode != 'RGB':
            img2 = img2.convert('RGB')
        
        # Konversi ke array numpy
        img1_array = np.array(img1)
        img2_array = np.array(img2)
        
        # Pastikan kedua array memiliki dimensi yang sama
        if img1_array.shape != img2_array.shape:
            print(f"Warning: Dimensi gambar berbeda. Original: {img1_array.shape}, Stego: {img2_array.shape}")
            img2 = img2.resize(img1.size)
            img2_array = np.array(img2)
        
        # Hitung MSE
        mse = np.mean((img1_array - img2_array) ** 2)
        
        # Hitung PSNR
        if mse == 0:
            psnr = float('inf')
        else:
            max_pixel = 255.0
            psnr = 20 * np.log10(max_pixel / np.sqrt(mse))
        
        # Evaluasi kualitas MSE
        print("\nHasil analisis kualitas gambar:")
        print(f"MSE: {mse:.6f}")
        if mse < 30:
            print("Kualitas MSE: Sangat Baik (tidak ada perubahan yang terlihat)")
        elif mse < 100:
            print("Kualitas MSE: Baik (perubahan gambar minimal)")
        elif mse < 500:
            print("Kualitas MSE: Cukup (perubahan pada gambar terlihat)")
        else:
            print("Kualitas MSE: Kurang Baik (perubahan gambar yang signifikan)")
        
        # Evaluasi kualitas PSNR
        print(f"PSNR: {psnr:.2f} dB")
        if psnr > 50:
            print("Kualitas PSNR: Sangat Baik (perubahan tidak terdeteksi atau tidak terlihat)")
        elif psnr > 40:
            print("Kualitas PSNR: Baik (perubahan hampir tidak terlihat)")
        elif psnr > 30:
            print("Kualitas PSNR: Cukup (perubahan minimal)")
        else:
            print("Kualitas PSNR: Kurang Baik (perubahan terlihat jelas)")
        
        return mse, psnr
        
    except Exception as e:
        print(f"Error saat menghitung MSE/PSNR: {str(e)}")
        print(f"Debug info - Image 1 mode: {img1.mode if 'img1' in locals() else 'unknown'}")
        print(f"Debug info - Image 2 mode: {img2.mode if 'img2' in locals() else 'unknown'}")
        print(f"Debug info - Array 1 shape: {img1_array.shape if 'img1_array' in locals() else 'unknown'}")
        print(f"Debug info - Array 2 shape: {img2_array.shape if 'img2_array' in locals() else 'unknown'}")
        return 0.0, float('inf')

# Initialize character table
init_char_table()

# Flask Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encode', methods=['POST'])
def encode():
    try:
        # Get form data
        message = request.form.get('message')
        key = request.form.get('key')
        image = request.files.get('image')

        # Print key to terminal
        print("\n[*] Encryption Key Used:", key)

        if not all([message, key, image]):
            return jsonify({
                'status': 'error',
                'message': 'Missing required fields'
            }), 400

        try:
            # Convert key to integer
            key = int(key)
        except ValueError:
            return jsonify({
                'status': 'error',
                'message': 'Encryption key harus berupa angka'
            }), 400

        # Save uploaded image
        filename = secure_filename(image.filename)
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image.save(image_path)

        # Encode the image
        try:
            output_path = encode_image(image_path, message, key)
            
            # Calculate MSE and PSNR
            mse, psnr = calculate_mse_psnr(image_path, output_path)

            # Get encrypted message
            encrypted_text = encrypt_custom(message, key)

            # Read the encoded image and convert to base64
            with open(output_path, 'rb') as img_file:
                encoded_image = base64.b64encode(img_file.read()).decode('utf-8')

            # Clean up temporary files
            os.remove(image_path)
            os.remove(output_path)

            return jsonify({
                'status': 'success',
                'image': f'data:image/png;base64,{encoded_image}',
                'mse': float(mse),
                'psnr': float(psnr),
                'encrypted_message': encrypted_text
            })

        except Exception as e:
            if os.path.exists(image_path):
                os.remove(image_path)
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/decode', methods=['POST'])
def decode():
    try:
        # Get form data
        key = request.form.get('key')
        image = request.files.get('image')

        # Print key to terminal
        print("\n[*] Decryption Key Used:", key)

        if not all([key, image]):
            return jsonify({
                'status': 'error',
                'message': 'Missing required fields'
            }), 400

        try:
            # Convert key to integer
            key = int(key)
        except ValueError:
            return jsonify({
                'status': 'error',
                'message': 'Decryption key harus berupa angka'
            }), 400

        # Save uploaded image
        filename = secure_filename(image.filename)
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image.save(image_path)

        try:
            # Decode the image
            result = decode_image(image_path, key)
            
            # Read the image and convert to base64 for preview
            with open(image_path, 'rb') as img_file:
                encoded_image = base64.b64encode(img_file.read()).decode('utf-8')
            
            # Clean up temporary file
            if os.path.exists(image_path):
                os.remove(image_path)

            if result['status'] == 'success':
                return jsonify({
                    'status': 'success',
                    'message': result['message'],
                    'encrypted_message': result.get('encrypted', ''),
                    'image': f'data:image/png;base64,{encoded_image}'
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': result['message'],
                    'image': f'data:image/png;base64,{encoded_image}'
                }), 400

        except Exception as e:
            if os.path.exists(image_path):
                os.remove(image_path)
            print(f"Decoding error: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': f'Error during decoding: {str(e)}'
            }), 500

    except Exception as e:
        print(f"General error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

if __name__ == '__main__':
    app.run(debug=True) 