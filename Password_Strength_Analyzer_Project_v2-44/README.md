# Password Strength Analyzer

## Features
- Password length checking
- Complexity checking
- Common-password dataset
- Predictable sequence detection
- Repeated-character detection
- 0-100 educational strength score
- Strong-password suggestions
- Randomly generated stronger password alternatives
- SQLite password history
- Password reuse prevention
- PBKDF2-HMAC-SHA256 password hashing with a unique random salt
- Plaintext passwords are never stored in the database

## Files
- `password_analyzer.py` - main Python application
- `common_passwords.csv` - small demo dataset of weak/common passwords
- `README.md` - project documentation

## Run
```bash
python password_analyzer.py
```

Python 3.8+ is recommended. No external packages are required.

## Database
The application automatically creates:
- `users`
- `password_history`

The SQLite database is:
`password_history.db`

Only password hashes and salts are stored.

The stronger-password generator creates random alternatives using Python's `secrets` module. Generated alternatives are displayed only and are not saved to the database.

## Important
This is an educational password analyzer. Its score is not a replacement for a production password-strength library such as zxcvbn or a breached-password screening service. For real applications, use a mature password policy, MFA/passkeys, secure password managers, rate limiting, and an established password hashing algorithm such as Argon2id.
