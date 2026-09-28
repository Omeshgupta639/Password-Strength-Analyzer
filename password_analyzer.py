"""
Password Strength Analyzer
Features:
1. Checks password length
2. Checks uppercase/lowercase/digit/special-character complexity
3. Detects common/weak passwords using a local dataset
4. Detects repeated characters and simple sequences
5. Gives a strength score and suggestions
6. Stores only salted PBKDF2 hashes in SQLite (never plaintext passwords)
7. Prevents reuse of passwords found in the user's password history
8. Allows adding a new password and checking it against history

Run:
    python password_analyzer.py
"""

import csv
import hashlib
import hmac
import os
import re
import sqlite3
import secrets
from pathlib import Path

DB_NAME = "password_history.db"
DATASET_NAME = "common_passwords.csv"
PBKDF2_ITERATIONS = 200_000



def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            password_hash BLOB NOT NULL,
            salt BLOB NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    return conn


def get_or_create_user(conn, username):
    username = username.strip()
    if not username:
        raise ValueError("Username cannot be empty.")

    conn.execute("INSERT OR IGNORE INTO users(username) VALUES (?)", (username,))
    conn.commit()

    row = conn.execute(
        "SELECT id FROM users WHERE username = ?", (username,)
    ).fetchone()
    return row[0]




def hash_password(password, salt=None):
    """Return (hash, salt). The plaintext password is never stored."""
    if salt is None:
        salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS
    )
    return password_hash, salt


def password_matches_hash(password, stored_hash, salt):
    candidate_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(candidate_hash, stored_hash)


def is_reused(conn, user_id, password):
    rows = conn.execute(
        "SELECT password_hash, salt FROM password_history WHERE user_id = ?",
        (user_id,)
    ).fetchall()

    for stored_hash, salt in rows:
        if password_matches_hash(password, stored_hash, salt):
            return True
    return False


def save_password_hash(conn, user_id, password):
    password_hash, salt = hash_password(password)
    conn.execute(
        """
        INSERT INTO password_history(user_id, password_hash, salt)
        VALUES (?, ?, ?)
        """,
        (user_id, password_hash, salt)
    )
    conn.commit()



def load_common_passwords(filename=DATASET_NAME):
    common = set()

    path = Path(filename)
    if not path.exists():
        return common

    with path.open("r", encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)
        for row in reader:
            password = row.get("password", "").strip().lower()
            if password:
                common.add(password)

    return common




def analyze_password(password, common_passwords):
    """
    Returns a dictionary containing all password analysis results.
    """

    checks = {
        "length_12_plus": len(password) >= 12,
        "length_16_plus": len(password) >= 16,
        "lowercase": bool(re.search(r"[a-z]", password)),
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "digit": bool(re.search(r"\d", password)),
        "special": bool(re.search(r"[^A-Za-z0-9]", password)),
    }

    normalized = password.lower()

    common = normalized in common_passwords

    
    repeated = bool(re.search(r"(.)\1\1", password))

    
    sequences = [
        "0123456789", "9876543210",
        "abcdefghijklmnopqrstuvwxyz",
        "zyxwvutsrqponmlkjihgfedcba",
        "qwerty", "asdfgh", "zxcvbn"
    ]
    sequential = any(seq in normalized for seq in sequences)

    
    score = 0

    if len(password) >= 8:
        score += 15
    if len(password) >= 12:
        score += 15
    if len(password) >= 16:
        score += 10

    score += 10 if checks["lowercase"] else 0
    score += 10 if checks["uppercase"] else 0
    score += 10 if checks["digit"] else 0
    score += 15 if checks["special"] else 0

    if common:
        score -= 45
    if repeated:
        score -= 10
    if sequential:
        score -= 15

    score = max(0, min(100, score))

    if common:
        strength = "Very Weak"
    elif score < 40:
        strength = "Weak"
    elif score < 60:
        strength = "Moderate"
    elif score < 80:
        strength = "Strong"
    else:
        strength = "Very Strong"

    suggestions = []

    if len(password) < 12:
        suggestions.append("Use at least 12 characters; 16+ is preferable.")
    if not checks["lowercase"]:
        suggestions.append("Add lowercase letters.")
    if not checks["uppercase"]:
        suggestions.append("Add uppercase letters.")
    if not checks["digit"]:
        suggestions.append("Add numbers.")
    if not checks["special"]:
        suggestions.append("Add special characters.")
    if common:
        suggestions.append("Avoid common or dictionary passwords.")
    if repeated:
        suggestions.append("Avoid repeating the same character three or more times.")
    if sequential:
        suggestions.append("Avoid predictable sequences such as 1234, qwerty, or abcd.")

    if not suggestions:
        suggestions.append("No basic weaknesses detected. Prefer a unique passphrase generated by a password manager.")

    return {
        "score": score,
        "strength": strength,
        "checks": checks,
        "common": common,
        "repeated": repeated,
        "sequential": sequential,
        "suggestions": suggestions,
    }





WORDS = [
    "River", "Falcon", "Orbit", "Cedar", "Matrix", "Quantum",
    "Rocket", "Forest", "Pixel", "Thunder", "Silver", "Nexus",
    "Galaxy", "Python", "Cipher", "Vertex", "Shadow", "Comet",
    "Summit", "Phoenix", "Network", "Secure", "Digital", "Cosmos"
]

def generate_stronger_alternatives(count=5):
    """
    Generate random stronger alternatives.
    These are suggestions only and are NOT stored in the database.
    """
    alternatives = []

    for _ in range(count):
        word1 = secrets.choice(WORDS)
        word2 = secrets.choice(WORDS)
        number = secrets.randbelow(9000) + 1000
        special = secrets.choice("!@#$%^&*_-+=")

        # Example: Falcon-Cosmos!4821
        candidate = f"{word1}-{word2}{special}{number}"

        # Avoid accidental duplicates.
        if candidate not in alternatives:
            alternatives.append(candidate)

    return alternatives


def show_stronger_alternatives():
    print("\n" + "=" * 55)
    print("STRONGER PASSWORD ALTERNATIVES")
    print("=" * 55)
    print("These are randomly generated suggestions.")
    print("Do not reuse them across different accounts.\n")

    alternatives = generate_stronger_alternatives(5)

    for number, password in enumerate(alternatives, start=1):
        print(f"{number}. {password}")

    print("\nTip: For real accounts, use a password manager to generate")
    print("and store a unique random password.")




def print_result(result, reused=False):
    print("\n" + "=" * 55)
    print("PASSWORD ANALYSIS RESULT")
    print("=" * 55)

    print(f"Score       : {result['score']}/100")
    print(f"Strength    : {result['strength']}")
    print(f"Common      : {'YES' if result['common'] else 'NO'}")
    print(f"Reused      : {'YES' if reused else 'NO'}")
    print("\nChecks:")

    labels = {
        "length_12_plus": "At least 12 characters",
        "length_16_plus": "At least 16 characters",
        "lowercase": "Lowercase letter",
        "uppercase": "Uppercase letter",
        "digit": "Number",
        "special": "Special character",
    }

    for key, label in labels.items():
        mark = "PASS" if result["checks"][key] else "FAIL"
        print(f"  [{mark:4}] {label}")

    print("\nSuggestions:")
    for suggestion in result["suggestions"]:
        print(f"  - {suggestion}")

    if reused:
        print("  - Do not reuse a previous password for this account.")




def main():
    print("=" * 55)
    print("        PASSWORD STRENGTH ANALYZER")
    print("=" * 55)
    print("For educational/security-learning purposes.")
    print("Do not enter a real production password into a classroom demo.")

    common_passwords = load_common_passwords()
    conn = get_connection()

    try:
        username = input("\nEnter username: ").strip()
        user_id = get_or_create_user(conn, username)

        while True:
            print("\nMENU")
            print("1. Analyze password")
            print("2. Analyze and save password to history")
            print("3. Check password reuse")
            print("4. Show password-history count")
            print("5. Generate stronger password alternatives")
            print("6. Exit")

            choice = input("Choose an option: ").strip()

            if choice == "1":
                password = input("Enter password: ")
                result = analyze_password(password, common_passwords)
                reused = is_reused(conn, user_id, password)
                print_result(result, reused)

            elif choice == "2":
                password = input("Enter password: ")
                result = analyze_password(password, common_passwords)
                reused = is_reused(conn, user_id, password)
                print_result(result, reused)

                if reused:
                    print("\nPassword was NOT saved because it was previously used.")
                elif result["score"] < 60 or result["common"]:
                    print("\nPassword was NOT saved because it is below the recommended strength.")
                else:
                    save_password_hash(conn, user_id, password)
                    print("\nPassword hash saved successfully.")
                    print("Plaintext password was NOT stored.")

            elif choice == "3":
                password = input("Enter password to check: ")
                reused = is_reused(conn, user_id, password)
                print(
                    "\nREUSED: This password was used before."
                    if reused
                    else "\nNOT REUSED: No matching password hash was found."
                )

            elif choice == "4":
                count = conn.execute(
                    "SELECT COUNT(*) FROM password_history WHERE user_id = ?",
                    (user_id,)
                ).fetchone()[0]
                print(f"\nStored password hashes for '{username}': {count}")

            elif choice == "5":
                show_stronger_alternatives()

            elif choice == "6":
                print("Exiting...")
                break

            else:
                print("Invalid choice. Select 1-6.")

    finally:
        conn.close()


if __name__ == "__main__":
    main()
