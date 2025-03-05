import numpy as np
import hashlib
import random
from sklearn.ensemble import RandomForestClassifier
from sklearn.datasets import fetch_openml
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from pyope.ope import OPE
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import matplotlib.pyplot as plt


choose = 0

# Load MNIST dataset
mnist = fetch_openml('mnist_784', version=1)
X, y = mnist.data, mnist.target.astype(int)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Train a Random Forest model
rf = RandomForestClassifier(n_estimators=3, random_state=42)
rf.fit(X_train, y_train)

# Generate OPE cipher from key seed with at least 256 bits
def generate_ope_cipher(key_seed):
    key = hashlib.sha512(key_seed.encode()).digest()[:32]  # 256-bit key
    return OPE(key)

# Generate RSA Keys for Proxy Re-Encryption
def generate_rsa_keys():
    alice_key = RSA.generate(2048)
    bob_key = RSA.generate(2048)
    return alice_key, bob_key

# Generate Encryption Keys
def generate_keys(num_trees):
    keys_dict = {}
    for i in range(num_trees):
        keys_dict[f'Kcomp_{i}'] = generate_ope_cipher(f'Kcomp_{i}')
        tree_hash = hashlib.sha512(f'Tree_{i}'.encode()).digest()[:32]
        keys_dict[f'Klocal_{i}'] = generate_ope_cipher(tree_hash.hex())
    keys_dict['Kvote'] = generate_ope_cipher('Kvote_shared')
    return keys_dict

# Encrypt Decision Tree Thresholds Using OPE
def encrypt_thresholds(thresholds, kcomp):
    return [kcomp.encrypt(t) for t in thresholds]

# Bob Encrypts Input Data Using OPE
def bob_encrypt_data(input_value, kcomp):
    return kcomp.encrypt(input_value)

# Encrypt Classification Results Using RSA
def encrypt_classification_result(classification, alice_pub_key):
    cipher_rsa = PKCS1_OAEP.new(alice_pub_key)
    ciphertext = cipher_rsa.encrypt(str(classification).encode())
    return ciphertext

# Proxy Re-Encryption (Klocal -> Kvote)
#Needs to be modified.
def proxy_reencrypt_rsa(ciphertext, alice_priv_key, bob_pub_key):
    cipher_rsa_decrypt = PKCS1_OAEP.new(alice_priv_key)
    decrypted_classification = cipher_rsa_decrypt.decrypt(ciphertext)
    cipher_rsa_encrypt = PKCS1_OAEP.new(bob_pub_key)
    reencrypted_ciphertext = cipher_rsa_encrypt.encrypt(decrypted_classification)
    return reencrypted_ciphertext

# Bob Decrypts Final Classification using RSA
def bob_decrypt_final_classification(ciphertext, bob_priv_key):
    cipher_rsa = PKCS1_OAEP.new(bob_priv_key)
    decrypted_classification = cipher_rsa.decrypt(ciphertext)
    return decrypted_classification.decode()

# Simulating the Secure Workflow
num_trees = 3
keys_dict = generate_keys(num_trees)
alice_key, bob_key = generate_rsa_keys()
trees = {}
for i, tree in enumerate(rf.estimators_):
    thresholds = [random.randint(1, 100) for _ in range(3)]
    encrypted_thresholds = encrypt_thresholds(thresholds, keys_dict[f'Kcomp_{i}'])
    trees[i] = {'thresholds': encrypted_thresholds}

#change this
bob_data = int(X_test[choose][0])  # Bob's input
encrypted_data = {i: bob_encrypt_data(bob_data, keys_dict[f'Kcomp_{i}']) for i in range(num_trees)}

# Alice Performs Secure Inference
results = {}
for i, tree in enumerate(rf.estimators_):
    #change this
    classification = int(tree.predict([X_test[choose]])[0])  # Use full MNIST feature vector
    results[i] = encrypt_classification_result(classification, alice_key.publickey())

# TTP Performs Proxy Re-Encryption using RSA
reencrypted_results = {}
for i in range(num_trees):
    reencrypted_classification = proxy_reencrypt_rsa(results[i], alice_key, bob_key.publickey())
    reencrypted_results[i] = reencrypted_classification

# Alice Performs Majority Voting
final_classification = max(set(reencrypted_results.values()), key=list(reencrypted_results.values()).count)

#change this
plt.imshow(X_test[choose].reshape(28, 28), cmap='gray')
plt.title("Test Image")
plt.show()

# Bob Decrypts the Final Classification using RSA
final_result = bob_decrypt_final_classification(final_classification, bob_key)
print("Final Classification Result for Bob:", final_result)
