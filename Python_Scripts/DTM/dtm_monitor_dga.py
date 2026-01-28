import random
import string
import encodings.idna # For Punycode generation

# Define common leetspeak substitutions (global for reusability)
LEETSPEAK_MAP = {
    'a': ['4', '@'],
    'e': ['3'],
    'i': ['1', '!'],
    'o': ['0'],
    's': ['5', '$'],
    't': ['7', '+'],
    'l': ['1'],
    'z': ['2']
}

# Define common typo-squatting substitutions (keyboard proximity, visual similarity) (global)
TYPO_SQUAT_MAP = {
    'a': ['q', 's', 'z'], 's': ['a', 'w', 'd', 'x', 'z'], 'd': ['s', 'w', 'e', 'f', 'c', 'x'],
    'f': ['d', 'e', 'r', 'g', 'v', 'c'], 'g': ['f', 'r', 't', 'h', 'b', 'v'], 'h': ['g', 't', 'y', 'j', 'n', 'b'],
    'j': ['h', 'y', 'u', 'k', 'm', 'n'], 'k': ['j', 'u', 'i', 'l', 'm'], 'l': ['k', 'i', 'o', 'p', 'a', 'e', 'f'], # Added 'a', 'e', 'f' for common substitutions
    'q': ['w', 'a'], 'w': ['q', 'a', 's', 'e'], 'e': ['w', 's', 'd', 'r'], 'r': ['e', 'd', 'f', 't'],
    't': ['r', 'f', 'g', 'y'], 'y': ['t', 'g', 'h', 'u'], 'u': ['y', 'h', 'j', 'i'], 'i': ['u', 'j', 'k', 'o'],
    'o': ['i', 'k', 'l', 'p', 'd'], # Added 'd' for 'goodgle.com'
    'p': ['o', 'l'], 'z': ['a', 's', 'x'], 'x': ['z', 's', 'd', 'c'],
    'c': ['x', 'd', 'f', 'v', 'r', 'k'], # Added 'r' and 'k' for common substitutions (e.g., office -> offier, offike)
    'v': ['c', 'f', 'g', 'b'], 'b': ['v', 'g', 'h', 'n'], 'n': ['b', 'h', 'j', 'm'],
    'm': ['n', 'j', 'k'],
    # Visually similar numbers/letters
    '1': ['l', 'i'],
    '0': ['o'],
    '5': ['s'],
    'g': ['d'] # Added 'd' for 'goodle.com'
}

# Homoglyph map for Punycode generation (simplified for common examples)
HOMOGLYPH_MAP = {
    'a': ['а', 'ɑ'],  # Cyrillic 'a', Latin 'alpha'
    'e': ['е'],       # Cyrillic 'e'
    'o': ['о', 'ο'],  # Cyrillic 'o', Greek 'omicron'
    'i': ['і', 'ı'],  # Cyrillic 'i', Turkish dotless 'i'
    'c': ['с'],       # Cyrillic 's'
    'p': ['р'],       # Cyrillic 'r'
    'x': ['х'],       # Cyrillic 'ha'
    'y': ['у'],       # Cyrillic 'u'
    'k': ['к'],       # Cyrillic 'k'
    'v': ['ѵ'],       # Cyrillic 'izhitsa'
    'h': ['һ'],       # Cyrillic 'h'
    'n': ['ո'],       # Armenian 'vo'
    'm': ['ṃ'],       # Devanagari 'm'
    'l': ['і', 'ĺ'],  # Cyrillic 'i', Latin 'l' with acute
    'g': ['ġ'],       # Latin 'g' with dot above
}

def apply_word_transformation(word, transform_type, chars_for_mod):
    """
    Applies a single random word-level transformation to a given word.
    Used internally by other generation functions.
    """
    if transform_type == "original":
        return word
    elif transform_type == "capitalize_first":
        return word.capitalize()
    elif transform_type == "uppercase":
        return word.upper()
    elif transform_type == "add_number":
        return f"{word}{random.randint(0, 99)}"
    elif transform_type == "insert_char" and len(word) < 15:
        pos = random.randint(0, len(word))
        char = random.choice(chars_for_mod)
        return word[:pos] + char + word[pos:]
    elif transform_type == "delete_char" and len(word) > 1:
        pos = random.randint(0, len(word) - 1)
        return word[:pos] + word[pos+1:]
    elif transform_type == "substitute_char" and len(word) > 0:
        pos = random.randint(0, len(word) - 1)
        char_to_substitute = word[pos].lower()
        if char_to_substitute in TYPO_SQUAT_MAP:
            new_char = random.choice(TYPO_SQUAT_MAP[char_to_substitute])
            return word[:pos] + new_char + word[pos+1:]
        return word # No substitution if char not in map
    elif transform_type == "transpose_chars" and len(word) >= 2:
        pos = random.randint(0, len(word) - 2)
        word_list = list(word)
        word_list[pos], word_list[pos+1] = word_list[pos+1], word_list[pos]
        return "".join(word_list)
    elif transform_type == "leetspeak":
        leeted_word = []
        for char in word:
            if char.lower() in LEETSPEAK_MAP and random.random() < 0.6:
                leeted_word.append(random.choice(LEETSPEAK_MAP[char.lower()]))
            else:
                leeted_word.append(char)
        return "".join(leeted_word)
    elif transform_type == "typo_squat_char":
        typo_word = []
        for char in word:
            if char.lower() in TYPO_SQUAT_MAP and random.random() < 0.6:
                typo_word.append(random.choice(TYPO_SQUAT_MAP[char.lower()]))
            else:
                typo_word.append(char)
        return "".join(typo_word)
    elif transform_type == "double_char" and len(word) > 0 and len(word) < 15:
        pos = random.randint(0, len(word) - 1)
        return word[:pos+1] + word[pos] + word[pos+1:]
    elif transform_type == "homoglyph_punycode" and len(word) > 0:
        # Only apply with a certain probability to avoid too many Punycode domains
        if random.random() < 0.7: # 70% chance to attempt homoglyph replacement
            homoglyphed_word_list = list(word)
            modified = False
            for i, char in enumerate(word):
                if char.lower() in HOMOGLYPH_MAP and random.random() < 0.4: # 40% chance to substitute a char
                    homoglyphed_word_list[i] = random.choice(HOMOGLYPH_MAP[char.lower()])
                    modified = True
            
            if modified:
                try:
                    # Encode the modified word part to Punycode
                    # The decode("ascii") is crucial to get the xn-- format string
                    return "".join(homoglyphed_word_list).encode("idna").decode("ascii")
                except Exception as e:
                    # In case of encoding error (e.g., invalid IDN char combo), return original word
                    return word
        return word # Return original if not modified or not chosen to modify
    return word # Fallback


def generate_typosquat_domains(target_domain, count=100):
    """
    Generates a list of typo-squatted domain variations for a given target domain.
    Includes variations in base name, weird TLDs, and subdomains.

    Args:
        target_domain (str): The main domain to generate variations for (e.g., "example.com").
        count (int): The number of domain variations to generate.

    Returns:
        list: A list of generated typosquatted domain names.
    """
    generated_domains = set() # Use a set to avoid duplicates
    
    # Split the target domain into name and TLD
    if '.' in target_domain:
        parts = target_domain.rsplit('.', 1)
        name_part = parts[0]
        original_tld = parts[1]
    else:
        name_part = target_domain
        original_tld = "com" # Default TLD if none provided

    # Common weird TLDs for dark web monitoring
    WEIRD_TLDS = [
        original_tld, # Include original TLD to maintain some similarity
        "onion", "xyz", "club", "info", "biz", "net", "org", "co", "io", "online",
        "site", "app", "tech", "store", "live", "link", "guru", "solutions",
        "top", "icu", "ru", # Some common problematic/alternative TLDs
        "cc", "ws", "tk", "ml", "ga", "cf", "gq" # Free/less regulated TLDs
    ]

    # Common subdomain prefixes
    SUBDOMAINS = [
        "", # No subdomain
        "www", "blog", "dev", "login", "secure", "mail", "admin", "web", "shop", "my",
        "test", "alpha", "beta", "cpanel", "vpn", "cdn", "download", "portal",
        "m", # Mobile
        "s1", "s2", # Generic servers
    ]

    chars_for_mod = string.ascii_lowercase + string.digits + "_-"

    # Define the set of transformations specifically for the domain's name part
    domain_name_transform_types = [
        "original", "capitalize_first", "uppercase",
        "insert_char", "delete_char", "substitute_char", "transpose_chars",
        "leetspeak", "typo_squat_char", "double_char", "homoglyph_punycode" # Added new transformations
    ]

    # Try to generate unique domains until the count is met
    while len(generated_domains) < count:
        varied_name_part = name_part

        # Apply 1 to 3 word-level transformations to the name part
        num_transforms_name = random.randint(1, 3) # Increased max transformations for more variety
        # Randomly select transformations to apply, ensure unique types if possible
        current_transform_types = random.sample(domain_name_transform_types, min(num_transforms_name, len(domain_name_transform_types)))
        
        for transform_type in current_transform_types:
            temp_varied_name_part = apply_word_transformation(varied_name_part, transform_type, chars_for_mod)
            # Only update if the transformation yielded a valid (non-empty) result
            if temp_varied_name_part:
                varied_name_part = temp_varied_name_part
            
            # Stop applying more transformations if the name part becomes too long for DNS
            if len(varied_name_part) > 63: # Max label length in DNS is 63 chars
                break

        # Choose a TLD
        chosen_tld = random.choice(WEIRD_TLDS)

        # Decide whether to add a subdomain
        chosen_subdomain = random.choice(SUBDOMAINS)
        
        # Construct the full domain
        if chosen_subdomain:
            domain = f"{chosen_subdomain}.{varied_name_part}.{chosen_tld}"
        else:
            domain = f"{varied_name_part}.{chosen_tld}"

        # Ensure the final domain is valid (max length 255) and add to set
        # Also ensure it doesn't start or end with a hyphen if it's not Punycode (IDNA conversion handles this)
        if len(domain) <= 255 and not (domain.startswith('-') or domain.endswith('-')):
            generated_domains.add(domain.lower()) # Ensure domains are lowercase and unique

    return list(generated_domains)[:count] # Convert to list and return required count


if __name__ == "__main__":
    print("--- Generating 1000 Typosquatted Domain Variations for 'google.com' ---")
    typosquatted_domains_dominic = generate_typosquat_domains("google.com", count=1000)
    for domain in typosquatted_domains_dominic:
        print(domain)

"""    print("\n--- Generating 1000 Typosquatted Domain Variations for 'sgpoolz.com.sg' ---")
    typosquatted_domains_samuel = generate_typosquat_domains("sgpoolz.com.sg", count=200)
    for domain in typosquatted_domains_samuel:
        print(domain)
"""
