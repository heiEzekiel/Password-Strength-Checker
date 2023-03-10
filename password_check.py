import passwordmeter
import requests
import hashlib
import math
import string
from collections import Counter
from password_strength import PasswordPolicy
from password_strength import PasswordStats
from zxcvbn import zxcvbn

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
    # create empty object to capture values
    pwd_details = {
        "hasLowerCase": False,
        "hasUpperCase": False,
        "hasSpChar": False,
        "hasNumber": False,
        "hasMinLength": False,
        "hasNotBeenLeaked": False,
        "hasNoSeqChar": False,
    }

    # leaked password check
    sha1_password = hashlib.sha1(password.encode()).hexdigest().upper()
    sha1_prefix = sha1_password[:5]
    sha1_suffix = sha1_password[5:]

    response = requests.get(f"https://api.pwnedpasswords.com/range/{sha1_prefix}")
    if response.status_code != 200:
        return "Error: Could not check password against leaked passwords database."

    leaked_passwords = response.text.split("\r\n")
    for temp_password in leaked_passwords:
        if sha1_suffix not in temp_password:
            pwd_details['hasNotBeenLeaked'] = True
        
    # length check
    if len(password) >= 8:
        pwd_details['hasMinLength'] = True

    # character types check
    has_lowercase = False
    has_uppercase = False
    has_number = False
    has_special = False
    
    # repeated characters check
    # if len(set(password)) != len(password):
    #     return "Weak password: Password should not contain repeated characters."

    # sequential characters check
    result = zxcvbn(password)

    if 'sequence' in result:
        sequences = result['sequence']
        for seq in sequences:
            if seq['pattern'] != 'sequence':
                pwd_details['hasNoSeqChar'] = True
    
    # character types check (cont.)

    for char in password:
        if char.islower():
            pwd_details['hasLowerCase'] = True
        elif char.isupper():
            pwd_details['hasUpperCase'] = True
        elif char.isdigit():
            pwd_details['hasNumber'] = True
        else:
            pwd_details['hasSpChar'] = True
    
    return pwd_details

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

def password_suggestion(password):
    result = zxcvbn(password)
    warning = result["feedback"]["suggestions"]
    return warning

def get_password_strength(password):
    strength = zxcvbn(password)['score']

    # Map strength score to a password strength level
    if strength == 0:
        level = 'Very weak'
    elif strength == 1:
        level = 'Weak'
    elif strength == 2:
        level = 'Moderate'
    elif strength == 3:
        level = 'Strong'
    else:
        level = 'Very strong'

    return level

def get_crack_time(password):
    result = zxcvbn(password)

    # Get the estimated crack time
    crack_time = result['crack_times_display']['offline_slow_hashing_1e4_per_second']

    return crack_time

def check_password_vulnerabilities(password):
    # Use zxcvbn to check password vulnerabilities
    result = zxcvbn(password)
    isSusceptibleToAttacks = result['sequence'];
    dictionaryWords = [];

    if (len(isSusceptibleToAttacks) != 0):
        for i in range(len(isSusceptibleToAttacks)):
            if (isSusceptibleToAttacks[i]["pattern"]) == 'dictionary': 
                dictionaryWords.append(isSusceptibleToAttacks[i]["token"]);
            elif (isSusceptibleToAttacks[i]["pattern"]) == 'spatial':
                return 'This password is susceptible to spatial attacks.'
            elif (isSusceptibleToAttacks[i]["pattern"]) == 'date':
                return 'This password is susceptible to date attacks.'
            elif (isSusceptibleToAttacks[i]["pattern"]) == 'repeat':
                return 'This password is susceptible to repeat attacks.'
            elif (isSusceptibleToAttacks[i]["pattern"]) == 'sequence':
                return 'This password is susceptible to sequence attacks.'
            else:
                return 'This password is susceptible to brute force attacks.'
        if (len(dictionaryWords)!= 0):
            unpacked = ", ".join(dictionaryWords)
            return unpacked + ' in password entered' + ' is susceptible to dictionary attacks.'
    else: 
        return 'This password is not susceptible to attacks.'

# password = str(input("Password: "))
# print("Guessing Entropy:", guessing_entropy(password))
# print("Shannon Entropy:", shannon_entropy(password))
# print("Markov Model Entropy:", markov_model_entropy(password, 2))

# print(custom_password_req(password))