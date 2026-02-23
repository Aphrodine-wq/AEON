"""Example Python file for AEON verification demo."""


def add(a: int, b: int) -> int:
    return a + b


def unsafe_divide(a: int, b: int) -> float:
    return a / b


def safe_divide(a: int, b: int) -> int:
    """
    Requires: b != 0
    """
    return a // b


def factorial(n: int) -> int:
    if n <= 1:
        return 1
    return n * factorial(n - 1)


class User:
    name: str
    email: str

    def __init__(self, name: str, email: str):
        self.name = name
        self.email = email


def create_user(name: str, email: str) -> bool:
    if not name:
        return False
    return True
