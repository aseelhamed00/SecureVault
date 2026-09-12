import secrets

# P-256 standard parameters
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

G = (GX, GY)

def point_is_on_curve(point):

    if point is None:
        return True

    if not isinstance(point, tuple):
        return False

    if len(point) != 2:
        return False

    x, y = point

    if not isinstance(x, int) or not isinstance(y, int):
        return False

    if x < 0 or x >= P:
        return False

    if y < 0 or y >= P:
        return False

    left = (y * y) % P

    right = (x * x * x + A * x + B) % P

    return left == right


def p256_validate_public(public_key):

    if not isinstance(public_key, bytes):
        return False

    if len(public_key) != 65:
        return False

    if public_key[0] != 0x04:
        return False

    x = int.from_bytes(public_key[1:33], "big")
    y = int.from_bytes(public_key[33:65], "big")

    if x >= P or y >= P:
        return False

    point = (x, y)

    return point_is_on_curve(point)


def point_add(P1, P2):

    if P1 is None:
        return P2

    if P2 is None:
        return P1

    if not point_is_on_curve(P1):
        raise ValueError("Invalid first point")

    if not point_is_on_curve(P2):
        raise ValueError("Invalid second point")

    x1, y1 = P1
    x2, y2 = P2

    #P+(-P) = infinity
    if x1 == x2 and (y1 + y2) % P == 0:
        return None

    #Point doubling
    if P1 == P2:
        if y1 == 0:
            return None

        numerator = (3 * x1 * x1 + A) % P
        denominator = (2 * y1) % P

    #Normal point addition
    else:
        numerator = (y2 - y1) % P
        denominator = (x2 - x1) % P

    inverse=pow(denominator,P - 2, P)

    slope=(numerator * inverse) % P

    x3 =(slope * slope - x1 - x2) % P
    y3 =(slope * (x1 - x3) - y1) % P

    result = (x3, y3)

    if not point_is_on_curve(result):
        raise ValueError("Point addition produced invalid point")

    return result


def scalar_mult(k, point):

    if not isinstance(k, int):
        raise TypeError("Scalar must be an integer")

    if k < 0:
        raise ValueError("Scalar must not be negative")

    if point is None:
        return None

    if not point_is_on_curve(point):
        raise ValueError("Invalid point")

    if k == 0:
        return None

    result = None
    current = point

    while k > 0:

        if k & 1:
            result = point_add(result, current)

        current = point_add(current, current)

        k >>= 1

    return result


def p256_keygen():

    private_scalar = secrets.randbelow(N - 1) + 1

    public_point = scalar_mult(private_scalar, G)

    if public_point is None:
        raise ValueError("Invalid generated public point")

    x, y = public_point

    private_key = private_scalar.to_bytes(32, "big")

    public_key = (
        b"\x04"
        + x.to_bytes(32, "big")
        + y.to_bytes(32, "big")
    )

    return private_key, public_key


def ecdh(private_key, public_key):
    
    if not isinstance(private_key, bytes):
        raise TypeError("Private key must be bytes")

    if len(private_key) != 32:
        raise ValueError("Private key must be 32 bytes")

    private_scalar = int.from_bytes(private_key, "big")

    if private_scalar <= 0 or private_scalar >= N:
        raise ValueError("Invalid private key")

    if not p256_validate_public(public_key):
        raise ValueError("Invalid public key")

    x = int.from_bytes(public_key[1:33], "big")
    y = int.from_bytes(public_key[33:65], "big")

    public_point = (x, y)

    shared_point = scalar_mult(private_scalar, public_point)

    if shared_point is None:
        raise ValueError("Invalid shared point")

    shared_x, shared_y = shared_point

    return shared_x.to_bytes(32, "big")