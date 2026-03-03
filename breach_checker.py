import hashlib
import requests


def check_breach(password: str) -> int:
    """
    Returns number of times password appeared in known breaches.
    Returns 0 if not found.
    """

    # 1. Hash password using SHA-1
    sha1_password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

    # 2. Split hash into prefix (first 5 chars) and suffix
    prefix = sha1_password[:5]
    suffix = sha1_password[5:]

    # 3. Query HIBP API using k-anonymity model
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)

    if response.status_code != 200:
        raise RuntimeError("Error fetching breach data")

    # 4. Compare suffix locally
    hashes = response.text.splitlines()

    for line in hashes:
        returned_suffix, count = line.split(":")
        if returned_suffix == suffix:
            return int(count)

    return 0

# if __name__ == "__main__":
#     test_password = input("Enter password to test: ")
#     count = check_breach(test_password)
#     print("Breach count:", count)