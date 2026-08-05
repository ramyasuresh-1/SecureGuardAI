"""Utilities for detecting common password patterns."""

import re
from collections import Counter

COMMON_WORDS = {
    "password",
    "secret",
    "admin",
    "welcome",
    "secure",
    "guard",
    "login",
    "letmein",
    "hello",
    "summer",
    "winter",
    "spring",
    "autumn",
    "qwerty",
    "flower",
    "sunshine",
}


def detect_dictionary_word(password: str) -> bool:
    """Return True when a password contains a common dictionary-style word."""
    if not password or not isinstance(password, str):
        return False

    lowered = password.lower()
    return any(word in lowered for word in COMMON_WORDS)


def detect_keyboard_pattern(password: str) -> bool:
    """Return True when a password contains a known keyboard sequence."""
    if not password or not isinstance(password, str):
        return False

    lowered = password.lower()
    patterns = ("qwerty", "asdf", "zxcv", "12345", "abcdef")
    return any(pattern in lowered for pattern in patterns)


def detect_birth_year(password: str) -> bool:
    """Return True when a password includes a likely birth year."""
    if not password or not isinstance(password, str):
        return False

    years = re.findall(r"(19\d{2}|20\d{2})", password)
    return bool(years)


def detect_repeated_characters(password: str) -> bool:
    """Return True when a password repeats at least one character."""
    if not password or not isinstance(password, str):
        return False

    counts = Counter(password.lower())
    return any(count > 1 for count in counts.values())


def detect_sequential_characters(password: str) -> bool:
    """Return True when a password contains a sequential letter or number run."""
    if not password or not isinstance(password, str):
        return False

    lowered = password.lower()
    if len(lowered) < 3:
        return False

    for index in range(len(lowered) - 2):
        first = lowered[index]
        second = lowered[index + 1]
        third = lowered[index + 2]

        if not (first.isalnum() and second.isalnum() and third.isalnum()):
            continue

        if first.isdigit() and second.isdigit() and third.isdigit():
            if int(first) + 1 == int(second) and int(second) + 1 == int(third):
                return True
            if int(first) - 1 == int(second) and int(second) - 1 == int(third):
                return True

        if first.isalpha() and second.isalpha() and third.isalpha():
            if ord(first) + 1 == ord(second) and ord(second) + 1 == ord(third):
                return True
            if ord(first) - 1 == ord(second) and ord(second) - 1 == ord(third):
                return True

    return False


def detect_consecutive_characters(password: str) -> bool:
    """Return True when adjacent characters are identical."""
    if not password or not isinstance(password, str):
        return False

    for index in range(len(password) - 1):
        if password[index] == password[index + 1]:
            return True

    return False
