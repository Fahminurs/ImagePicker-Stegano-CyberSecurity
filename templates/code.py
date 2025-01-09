from PIL import Image
import numpy as np
import os
import time
import psutil
import tracemalloc

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

# Tambahkan decorator ke fungsi encode_image
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

# Tambahkan decorator ke fungsi decode_image
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
                            encrypted_text, original_key, _ = message.split('|')
                            original_key = int(original_key)
                            
                            # Dekripsi pesan dengan kunci yang dimasukkan
                            decrypted_message = decrypt_custom(encrypted_text, input_key)
                            
                            # Verifikasi key dan tampilkan hasil
                            if original_key != input_key:
                                # Langsung return tanpa monitoring jika kunci salah
                                return {
                                    'status': 'error',
                                    'message': 'Kunci yang dimasukkan salah!',
                                    'decrypted': decrypted_message,
                                    'encrypted': encrypted_text
                                }
                            else:
                                # Lanjutkan dengan monitoring dan analisis jika kunci benar
                                return {
                                    'status': 'success',
                                    'message': decrypted_message,
                                    'encrypted': encrypted_text
                                }
                        except:
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

def main():
    # Inisialisasi tabel karakter
    init_char_table()
    
    while True:
        print("\nProgram Steganografi dengan Kriptografi")
        print("1. Enkripsi dan Sisipkan Pesan")
        print("2. Dekripsi Pesan dari Gambar")
        print("3. Keluar")
        
        choice = input("Pilih menu (1-3): ")
        
        if choice == '1':
            image_path = input("Masukkan nama file gambar: ")
            try:
                key = int(input("Masukkan kunci: "))
                secret_text = input("Masukkan pesan rahasia: ")
                
                print("\nProses Enkripsi:")
                print(f"Plaintext: {secret_text}")
                print(f"Jumlah karakter: {len(secret_text)}")
                encrypted_text = encrypt_custom(secret_text, key)
                print(f"Ciphertext: {encrypted_text}")
                print(f"Jumlah karakter: {len(encrypted_text)}")
                print("\nMenyisipkan pesan ke dalam gambar...")
                
                output_path = encode_image(image_path, secret_text, key)
                print(f"Pesan berhasil disisipkan! Gambar tersimpan sebagai: {output_path}")
                
            except ValueError as ve:
                print(f"Error: {str(ve)}")
            except Exception as e:
                print(f"Terjadi kesalahan: {str(e)}")
                
        elif choice == '2':
            image_path = input("Masukkan nama file gambar (PNG): ")
            try:
                if not image_path.startswith("encoded_"):
                    print("PERINGATAN: File gambar sebaiknya hasil dari proses enkripsi (diawali dengan 'encoded_')")
                
                key = int(input("Masukkan kunci: "))
                
                print("\nProses Dekripsi:")
                result = decode_image(image_path, key)
                if result:
                    if result['status'] == 'error':
                        print(f"\nError: {result['message']}")
                        if 'decrypted' in result:
                            print(f"Hasil dekripsi dengan kunci yang salah: {result['decrypted']}")
                            print(f"Pesan terenkripsi: {result['encrypted']}")
                    else:
                        original_path = image_path.replace("encoded_", "")
                        if os.path.exists(original_path):
                            mse, psnr = calculate_mse_psnr(original_path, image_path)
                        print(f"Pesan yang ditemukan: {result['message']}")
                        print(f"Jumlah karakter: {len(result['message'])}")
                else:
                    print("Tidak ada pesan yang ditemukan dalam gambar")
            except ValueError as ve:
                print(f"Error: {str(ve)}")
            except Exception as e:
                print(f"Terjadi kesalahan: {str(e)}")
                
        elif choice == '3':
            print("Terima kasih telah menggunakan program ini!")
            break
        
        else:
            print("Pilihan tidak valid!")

if __name__ == "__main__":
    main()

