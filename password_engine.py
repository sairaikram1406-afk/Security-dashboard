from zxcvbn import zxcvbn
import secrets
import string
import math
from typing import Optional


# -----------------------------
# EXISTING FEATURE (UNCHANGED)
# -----------------------------

def analyze_password(password: str) -> dict:
    result = zxcvbn(password)

    return {
        "score": result["score"],  # 0 (weak) → 4 (strong)
        "guesses": result["guesses"],
        "crack_time": result["crack_times_display"]["offline_fast_hashing_1e10_per_second"],
        "feedback": result["feedback"]
    }


# -----------------------------
# NEW FEATURE 3
# Advanced Password Generator
# -----------------------------

class PasswordGenerator:

    def __init__(self):
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?/"

    def generate_password(
        self,
        length: int = 16,
        use_lower: bool = True,
        use_upper: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True,
        target_entropy_bits: Optional[int] = None,
        avoid_ambiguous: bool = False
    ) -> dict:

        charset = self._build_charset(
            use_lower,
            use_upper,
            use_digits,
            use_symbols,
            avoid_ambiguous
        )

        if not charset:
            raise ValueError("Character set cannot be empty.")

        if target_entropy_bits:
            length = self._length_for_entropy(len(charset), target_entropy_bits)

        # Ensure at least one character from each selected category
        password_chars = []

        if use_lower:
            password_chars.append(secrets.choice(self.lowercase))
        if use_upper:
            password_chars.append(secrets.choice(self.uppercase))
        if use_digits:
            password_chars.append(secrets.choice(self.digits))
        if use_symbols:
            password_chars.append(secrets.choice(self.symbols))

        # Fill remaining length
        while len(password_chars) < length:
            password_chars.append(secrets.choice(charset))

        # Shuffle to remove predictable order
        secrets.SystemRandom().shuffle(password_chars)

        password = ''.join(password_chars)

        entropy = self._calculate_entropy(len(charset), length)

        return {
            "password": password,
            "length": length,
            "charset_size": len(charset),
            "entropy_bits": round(entropy, 2)
        }

    # -----------------------------
    # Internal Helpers
    # -----------------------------

    def _build_charset(
        self,
        use_lower: bool,
        use_upper: bool,
        use_digits: bool,
        use_symbols: bool,
        avoid_ambiguous: bool
    ) -> str:

        charset = ""

        if use_lower:
            charset += self.lowercase
        if use_upper:
            charset += self.uppercase
        if use_digits:
            charset += self.digits
        if use_symbols:
            charset += self.symbols

        if avoid_ambiguous:
            ambiguous = "l1I0O"
            charset = ''.join(c for c in charset if c not in ambiguous)

        return charset

    def _calculate_entropy(self, charset_size: int, length: int) -> float:
        return length * math.log2(charset_size)

    def _length_for_entropy(self, charset_size: int, target_entropy_bits: int) -> int:
        return math.ceil(target_entropy_bits / math.log2(charset_size))
    

if __name__ == "__main__":
     gen = PasswordGenerator()
     result = gen.generate_password(target_entropy_bits=100)
     print("Generated Password:", result)