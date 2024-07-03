import hashlib

# Function to read passwords from a file
def read_passwords(filename):
    with open(filename, 'r') as f:
        passwords = f.read().splitlines()
    return passwords

# Function to perform dictionary attack
def dictionary_attack(hash_to_crack, dictionary):
    for password in dictionary:
        # Calculate hash of the current password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        # Check if the hashed password matches the hash we are trying to crack
        if hashed_password == hash_to_crack:
            return password
    return None

# Function to perform brute-force attack
def brute_force_attack(hash_to_crack, max_length=4):
    characters = "abcdefghijklmnopqrstuvwxyz0123456789"
    for length in range(1, max_length + 1):
        for password in generate_passwords(characters, length):
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            if hashed_password == hash_to_crack:
                return password
    return None

# Function to generate passwords for brute-force attack
def generate_passwords(characters, length):
    if length == 1:
        return characters
    else:
        passwords = []
        shorter_passwords = generate_passwords(characters, length - 1)
        for character in characters:
            for shorter_password in shorter_passwords:
                passwords.append(shorter_password + character)
        return passwords

if __name__ == "__main__":
    # Assume the hash we are trying to crack is known (e.g., obtained from a database)
    hash_to_crack = "2b5d365cb1b2357232c78f70a5ee18650d78549d2ecb5006da6615b9d8bf9f5d"
    
    # Path to the dictionary file
    dictionary_file = "passwords.txt"
    
    # Read the dictionary of passwords from file
    dictionary = read_passwords(dictionary_file)
    
    # Attempt dictionary attack
    cracked_password = dictionary_attack(hash_to_crack, dictionary)
    
    if cracked_password:
        print(f"Password cracked using dictionary attack: {cracked_password}")
    else:
        print("Password not found in dictionary.")
    
    # Attempt brute-force attack
    max_length = 4  # Adjust the maximum length of passwords to try
    cracked_password = brute_force_attack(hash_to_crack, max_length)
    
    if cracked_password:
        print(f"Password cracked using brute-force attack: {cracked_password}")
    else:
        print("Password not cracked using brute-force attack.")
