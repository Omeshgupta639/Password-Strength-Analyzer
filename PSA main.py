import sqlite3
import hashlib
import secrets
import string
import re
import getpass

DATABASE = "password_history.db"


def create_database():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()




def hash_password(password, salt=None):
    """
    Hash password using PBKDF2-HMAC-SHA256.
    The actual password is never stored in the database.
    """

    if salt is None:
        salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600000
    )

    return password_hash, salt

def password_was_used(username, password):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT password_hash, salt
        FROM password_history
        WHERE username = ?
    """, (username,))

    records = cursor.fetchall()
    conn.close()

    for stored_hash, stored_salt in records:

        salt = bytes.fromhex(stored_salt)

        new_hash, _ = hash_password(password, salt)

        if secrets.compare_digest(
            new_hash.hex(),
            stored_hash
        ):
            return True

    return False




def save_password(username, password):

    password_hash, salt = hash_password(password)

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO password_history
        (username, password_hash, salt)
        VALUES (?, ?, ?)
    """, (
        username,
        password_hash.hex(),
        salt.hex()
    ))

    conn.commit()
    conn.close()

def analyze_password(password):

    score = 0
    suggestions = []

    if len(password) >= 12:
        score += 2

    elif len(password) >= 8:
        score += 1

    else:
        suggestions.append(
            "Use at least 8 characters."
        )

    

    if re.search(r"[A-Z]", password):
        score += 1

    else:
        suggestions.append(
            "Add at least one uppercase letter."
        )

    

    if re.search(r"[a-z]", password):
        score += 1

    else:
        suggestions.append(
            "Add at least one lowercase letter."
        )

    

    if re.search(r"[0-9]", password):
        score += 1

    else:
        suggestions.append(
            "Add at least one number."
        )

    

    if re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=/\\[\]]",
                 password):

        score += 1

    else:
        suggestions.append(
            "Add at least one special character."
        )

    

    if len(password) > 0:

        unique_ratio = len(set(password)) / len(password)

        if unique_ratio < 0.6:

            score -= 1

            suggestions.append(
                "Avoid excessive repeated characters."
            )

    

    common_passwords = {
        "password",
        "password123",
        "123456",
        "12345678",
        "123456789",
        "qwerty",
        "qwerty123",
        "admin",
        "admin123",
        "letmein",
        "welcome",
        "abc123",
        "iloveyou"
    }

    if password.lower() in common_passwords:

        return (
            "Very Weak",
            0,
            ["This is a commonly used password."]
        )

    

    sequences = [
        "123456",
        "abcdef",
        "qwerty",
        "654321",
        "fedcba"
    ]

    password_lower = password.lower()

    for sequence in sequences:

        if sequence in password_lower:

            score -= 1

            suggestions.append(
                "Avoid predictable sequences."
            )

            break

    

    if score <= 2:
        strength = "Weak"

    elif score <= 4:
        strength = "Moderate"

    elif score <= 5:
        strength = "Strong"

    else:
        strength = "Very Strong"

    return strength, score, suggestions


def generate_strong_password(length=16):

    if length < 12:
        length = 12

    uppercase = secrets.choice(string.ascii_uppercase)
    lowercase = secrets.choice(string.ascii_lowercase)
    number = secrets.choice(string.digits)
    special = secrets.choice("!@#$%^&*")

    remaining_characters = (
        string.ascii_letters +
        string.digits +
        "!@#$%^&*"
    )

    remaining = ''.join(
        secrets.choice(remaining_characters)
        for _ in range(length - 4)
    )

    password = (
        uppercase +
        lowercase +
        number +
        special +
        remaining
    )

    # Securely shuffle the password
    password_list = list(password)
    secrets.SystemRandom().shuffle(password_list)

    return ''.join(password_list)




def display_analysis(password):

    strength, score, suggestions = analyze_password(password)

    print("\n-----------------------------------------")
    print("PASSWORD ANALYSIS")
    print("-----------------------------------------")

    print("Strength :", strength)
    print("Score    :", score, "/ 7")

    print("\nPassword Requirements:")

    print(
        "Length >= 8          :",
        "PASS" if len(password) >= 8 else "FAIL"
    )

    print(
        "Uppercase letter     :",
        "PASS" if re.search(r"[A-Z]", password) else "FAIL"
    )

    print(
        "Lowercase letter     :",
        "PASS" if re.search(r"[a-z]", password) else "FAIL"
    )

    print(
        "Number               :",
        "PASS" if re.search(r"[0-9]", password) else "FAIL"
    )

    print(
        "Special character    :",
        "PASS" if re.search(
            r"[!@#$%^&*(),.?\":{}|<>_\-+=/\\[\]]",
            password
        ) else "FAIL"
    )

    if suggestions:

        print("\nSuggestions:")

        for suggestion in suggestions:
            print("-", suggestion)

    else:

        print(
            "\nYour password satisfies "
            "the basic security requirements."
        )

    print("-----------------------------------------")



def change_password():

    username = input("\nEnter username: ").strip()

    if not username:

        print("Username cannot be empty.")
        return

    password = getpass.getpass(
        "Enter new password: "
    )

    if not password:

        print("Password cannot be empty.")
        return

    # Analyze password
    display_analysis(password)

    # Check strength
    strength, score, suggestions = analyze_password(password)

    if strength in ["Weak", "Very Weak"]:

        print(
            "\nPassword is too weak. "
            "Please choose a stronger password."
        )

        return

    # Check password history
    if password_was_used(username, password):

        print(
            "\nERROR: This password was used previously."
        )

        print(
            "Please choose a new password."
        )

        return

    # Save password hash
    save_password(username, password)

    print(
        "\nSUCCESS: Password accepted and securely stored."
    )

    print(
        "The plaintext password was NOT stored in the database."
    )




def generate_password():

    try:

        length = int(
            input(
                "\nEnter desired password length "
                "(minimum 12): "
            )
        )

    except ValueError:

        print("Please enter a valid number.")
        return

    password = generate_strong_password(length)

    print("\nGenerated Strong Password:")
    print(password)

    print(
        "\nIMPORTANT: Store this password securely."
    )




def view_history():

    username = input("\nEnter username: ").strip()

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM password_history
        WHERE username = ?
    """, (username,))

    count = cursor.fetchone()[0]

    conn.close()

    print(
        f"\nPassword history records for {username}: {count}"
    )

    print(
        "Only password hashes are stored; "
        "the actual passwords cannot be displayed."
    )




def main():

    create_database()

    while True:

        print("\n")
        print("==========================================")
        print("       PASSWORD STRENGTH ANALYZER")
        print("==========================================")
        print("1. Analyze / Save New Password")
        print("2. Generate Strong Password")
        print("3. View Password History Count")
        print("4. Exit")
        print("==========================================")

        choice = input(
            "Enter your choice: "
        ).strip()

        if choice == "1":

            change_password()

        elif choice == "2":

            generate_password()

        elif choice == "3":

            view_history()

        elif choice == "4":

            print(
                "\nThank you for using "
                "Password Strength Analyzer."
            )

            break

        else:

            print(
                "\nInvalid choice. "
                "Please select 1-4."
            )


if __name__ == "__main__":
    main()
