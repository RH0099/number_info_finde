import math, random, re
from collections import Counter

def digit_entropy(n):
    s = str(abs(n))
    freq = Counter(s)
    L = len(s)
    return round(-sum((c/L)*math.log2(c/L) for c in freq.values()), 4)

def digital_root(n):
    return 1 + (n - 1) % 9 if n else 0

def miller_rabin(n, k=5):
    if n < 2:
        return False
    for p in (2,3,5,7,11,13,17,19,23):
        if n % p == 0:
            return n == p
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def classify(n):
    ent = digit_entropy(n)
    length = len(str(abs(n)))

    if length in (4,6):
        id_type = "OTP / PIN"
    elif length in (10,11):
        id_type = "Phone / Account"
    elif length >= 16:
        id_type = "Token / Key"
    else:
        id_type = "Generic ID"

    crypto = "High" if miller_rabin(n) and ent > 3.2 else \
             "Low" if ent < 2.4 else "Medium"

    origin = "Human" if ent < 2.3 else "System" if ent < 3.0 else "Random"

    fraud = []
    if len(set(str(n))) <= 3:
        fraud.append("Low digit diversity")
    if ent < 2.2:
        fraud.append("Low entropy")

    return {
        "number": n,
        "entropy": ent,
        "digital_root": digital_root(n),
        "id_type": id_type,
        "crypto_strength": crypto,
        "origin": origin,
        "fraud_flags": fraud or ["None"]
  }
