import passwordmeter
import requests
import hashlib
import math
import string
from collections import Counter
from password_strength import PasswordPolicy
from password_strength import PasswordStats

def password_check(password):
    #Password Strength Lib
    #Policy Settings
    policy = PasswordPolicy.from_names(
        length=8,  # min length: 8
        uppercase=2,  # need min. 2 uppercase letters
        numbers=2,  # need min. 2 digits
        special=2,  # need min. 2 special characters
        nonletters=2,  # need min. 2 non-letter characters (digits, specials, anything)
    )    
    #Password Stats 
    result1 = PasswordStats(password)
    
    #Password Meter Lib
    strength, improvements = passwordmeter.test(password)
    pass

def custom_password_req(password):
    # leaked password check
    sha1_password = hashlib.sha1(password.encode()).hexdigest().upper()
    sha1_prefix = sha1_password[:5]
    sha1_suffix = sha1_password[5:]

    response = requests.get(f"https://api.pwnedpasswords.com/range/{sha1_prefix}")
    if response.status_code != 200:
        return "Error: Could not check password against leaked passwords database."
    
    leaked_passwords = response.text.split("\r\n")
    for temp_password in leaked_passwords:
        if sha1_suffix in temp_password:
            return "Weak password: Password has been leaked and should not be used."
        
    # length check
    if len(password) < 8:
        return "Weak password: Password must be at least 8 characters long."

    # character types check
    has_lowercase = False
    has_uppercase = False
    has_number = False
    has_special = False
    
    # repeated characters check
    # if len(set(password)) != len(password):
    #     return "Weak password: Password should not contain repeated characters."
    
    # sequential characters check
    sequences = ["123", "234", "345", "456", "567", "678", "789", "890",
                 "qwerty", "asdfgh", "zxcvbn", "qazwsx", "edcrfv", "tgbnhy"]
    
    for sequence in sequences:
        if sequence in password.lower():
            return "Weak password: Password should not contain sequential characters."
    
    # character types check (cont.)

    for char in password:
        if char.islower():
            has_lowercase = True
        elif char.isupper():
            has_uppercase = True
        elif char.isdigit():
            has_number = True
        else:
            has_special = True
    
    if not has_lowercase:
        return "Weak password: Password must contain at least one lowercase letter."
    elif not has_uppercase:
        return "Weak password: Password must contain at least one uppercase letter."
    elif not has_number:
        return "Weak password: Password must contain at least one number."
    elif not has_special:
        return "Weak password: Password must contain at least one special character."
    
    return "Strong password"

def guessing_entropy(password):
    # Count the number of possible characters
    characters = string.ascii_letters + string.digits + string.punctuation
    char_count = len(characters)
    
    # Calculate the entropy of the password
    entropy = len(password) * math.log2(char_count)
    return entropy

def shannon_entropy(password):
    # Count the frequency of each character in the password
    freq = Counter(password)
    # Calculate the probability of each character
    probs = [float(freq[c]) / len(password) for c in freq]
    # Calculate the entropy of the password
    entropy = -sum(p * math.log2(p) for p in probs)
    return entropy * len(password)

def markov_model_entropy(password, order):
    # Generate a dictionary of character pairs and their frequencies
    freq = Counter(password[i:i+order] for i in range(len(password)-order+1))
    # Calculate the probability of each character pair
    probs = [float(freq[c]) / (len(password)-order+1) for c in freq]
    # Calculate the entropy of the password
    entropy = -sum(p * math.log2(p) for p in probs)
    return entropy * len(password)


# password = str(input("Password: "))
# print("Guessing Entropy:", guessing_entropy(password))
# print("Shannon Entropy:", shannon_entropy(password))
# print("Markov Model Entropy:", markov_model_entropy(password, 2))

# print(custom_password_req(password))