import json
import re
import secrets
import sys
import time
import unittest
from Crypto.Util.number import getPrime, isPrime
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (Ed25519PrivateKey, Ed25519PublicKey,)

PROTOCOL = "DH-CLASSROOM-AUTH-v1"
MAX_BYTES = 4096


class ProtocolError(Exception):
    pass

def is_int(x):
    return type(x) is int

# step 1: square and multiply

def modular_exponentiation(base, exponent, modulus):
    if not all(is_int(x) for x in (base, exponent, modulus)):
        raise TypeError("Integers Only")
    if exponent < 0 or modulus <= 0:
        raise ValueError("Exponent must be >= 0 and modulus > 0")
    result = 1 % modulus
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent //= 2
    return result

# step 2: library primes + received modulus validation

def generate_prime(bits=16):
    if not is_int(bits) or not 16 <= bits <= 32:
        raise ValueError("Prime size must be between 16 and 32 bits")
    p = getPrime(bits, randfunc=secrets.token_bytes)
    assert p.bit_length() == bits and p % 2 == 1
    return p

def validate_modulus(p, fixture=False):
    if not is_int(p):
        raise ProtocolError("p must be an integer")
    if not (16 <= p.bit_length() <= 32 or (fixture and p == 23)):
        raise ProtocolError("p has a disallowed bit length")
    if p % 2 == 0 or not isPrime(p):
        raise ProtocolError("p is not prime")

# step 3 and 4: factoring and generators

def prime_factors(n):
    if not is_int(n) or n < 1:
        raise ValueError("n must be a positive integer")
    out = set()
    d = 2
    while d * d <= n:
        if n % d == 0:
            out.add(d)
            while n % d == 0:
                n //= d
        d += 1 if d == 2 else 2
    if n > 1:
        out.add(n)
    return out

def is_generator(g, p, factors):
    return is_int(g) and 2 <= g <= p - 2 and all(modular_exponentiation(g, (p-1) // r, p) != 1 for r in factors)

def find_generator(p, factors=None):
    factors = factors or prime_factors(p-1)
    return next(g for g in range(2,p-1) if is_generator(g,p, factors))

# step 5: DH keys

def dh_keypair(p, g):
    while True:
        x = secrets.randbelow(p-3) + 2
        X = modular_exponentiation(g, x, p)
        if 2 <= X <= p - 2:
            return x, X

def in_range(v,p):
    return is_int(v) and 2 <= v <= p - 2

# step 7: strict encoding and validation

def encode(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def _no_dupes(pairs):
    d = dict(pairs)
    if len(d) != len(pairs):
        raise ProtocolError("duplicate JSON key")
    return d

def check(d, schema):
    if not isinstance(d, dict) or set(d) != set(schema):
        raise ProtocolError("Unexpected or missing fields")
    for k, t in schema.items():
        v = d[k]
        ok = (is_int(v) and 0 <= v.bit_length() <= 32 if t == "int" else
              isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v) is not None
              if t == "nonce" else isinstance(v, t))

        if not ok:
            raise ProtocolError(f"bad field {k}")

TRANSCRIPT = {"protocol": str, "initiator": str, "responder": str, "p": "int",
              "g": "int", "A": "int", "B": "int", "nonce_A": "nonce", "nonce_B": "nonce"}
SCHEMAS = {
    "init": {"protocol": str, "type": str, "initiator": str, "responder": str,
             "p": "int", "g": "int", "A": "int", "nonce_A": "nonce"},
    "response": {"type": str, "transcript": dict},
    "finish": {"type": str, "transcript": dict},
}       

# step 6, 8, 9: participants, signatures, sessions

class Party:
    def __init__(self, name, key, peer, peer_key, fixture=False):
        self.name = name
        self.key = key
        self.peer = peer
        self.peer_key = peer_key

        self.fixture = fixture
        self.session = None
        self.secret = None

        self.pending = {}
        self.completed = set()

    def _send(self, payload):
        return encode({"payload": payload, "sig": self.key.sign(encode(payload)).hex()})

    # bob and alice messages

    def _open(self, raw, kind):

        if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:

            raise ProtocolError("bad or oversized message")
        
        try:
        
            msg = json.loads(raw.decode(), object_pairs_hook=_no_dupes)
        
        except ValueError:
        
            raise ProtocolError("malformed JSON")
        
        check(msg, {"payload": dict, "sig": str})
        
        pl = msg["payload"]
        
        check(pl, SCHEMAS[kind])
        
        t = pl if kind == "init" else pl["transcript"]
        
        if kind != "init":
        
            check(t, TRANSCRIPT)
        
        if pl["type"] != kind or t["protocol"] != PROTOCOL or \
                (t["initiator"], t["responder"]) != ("Alice", "Bob"):
        
            raise ProtocolError("wrong type, protocol or identities")
        
        try:
        
            self.peer_key.verify(bytes.fromhex(msg["sig"]), encode(pl))
        
        except (InvalidSignature, ValueError):
        
            raise ProtocolError("signature INVALID")
        
        return t
 
    def initiate(self, bits=16, p=None, g=None):               
        
        p = p or generate_prime(bits)
        
        validate_modulus(p, self.fixture)
        
        g = g or find_generator(p)
        
        a, A = dh_keypair(p, g)
        
        n = secrets.token_bytes(32).hex()
        
        self.session = dict(p=p, g=g, a=a, A=A, nonce_A=n)
        
        return self._send({"protocol": PROTOCOL, "type": "init", "initiator": "Alice", "responder": "Bob", "p": p, "g": g, "A": A, "nonce_A": n})
 
    def handle_init(self, raw):                                
        
        t = self._open(raw, "init")
        
        validate_modulus(t["p"], self.fixture)
        
        if not is_generator(t["g"], t["p"], prime_factors(t["p"] - 1)):
        
            raise ProtocolError("g is not a generator")
        
        if not in_range(t["A"], t["p"]):
        
            raise ProtocolError("A out of range")
        
        b, B = dh_keypair(t["p"], t["g"])
        
        tr = {k: t[k] for k in ("protocol", "initiator", "responder", "p", "g", "A", "nonce_A")}
        
        tr.update(B=B, nonce_B=secrets.token_bytes(32).hex())
        
        self.pending[tr["nonce_B"]] = dict(b=b, t=tr)
        
        return self._send({"type": "response", "transcript": tr})
 
    def handle_response(self, raw):                            
        
        s, self.session = self.session, None                   
        
        if not s:
        
            raise ProtocolError("no pending session")
        
        t = self._open(raw, "response")
        
        if any(t[k] != s[k] for k in ("p", "g", "A", "nonce_A")):
        
            raise ProtocolError("response does not match pending session")
        
        if not in_range(t["B"], s["p"]):
        
            raise ProtocolError("B out of range")
        
        self.secret = modular_exponentiation(t["B"], s["a"], s["p"])
        
        return self._send({"type": "finish", "transcript": t})
 
    def handle_finish(self, raw):                              
        
        t = self._open(raw, "finish")
        
        if t["nonce_B"] in self.completed:
        
            raise ProtocolError("session already completed")
        
        rec = self.pending.pop(t["nonce_B"], None)             
        
        if rec is None or rec["t"] != t:
        
            raise ProtocolError("no matching pending session / transcript mismatch")
        
        self.completed.add(t["nonce_B"])
        
        self.secret = modular_exponentiation(t["A"], rec["b"], t["p"])

def make_parties(fixture=False):
    
    ak = Ed25519PrivateKey.generate()
    bk = Ed25519PrivateKey.generate()
    
    return (Party("Alice", ak, "Bob", bk.public_key(), fixture),
    
            Party("Bob", bk, "Alice", ak.public_key(), fixture))
 
 
def run_exchange(alice, bob, **kw):
   
    m3 = alice.handle_response(bob.handle_init(alice.initiate(**kw)))
    
    bob.handle_finish(m3)
    
    return m3
 
 
def tamper(raw, *path, value):
    
    msg = json.loads(raw)
    node = msg["payload"]
    for k in path[:-1]:
        node = node[k]
    node[path[-1]] = value
    return encode(msg) 

# step 10: EVEEE

def eve_unauthenticated(p=23, g=5, a=6, b=15, e1=3, e2=7):
    E1 = modular_exponentiation(g, e1, p)
    E2 = modular_exponentiation(g, e2, p)
    A = modular_exponentiation(g, a, p)
    B = modular_exponentiation(g, b, p)
    alice = modular_exponentiation(E1, a, p)  
    bob = modular_exponentiation(E2, b, p)   
    eve_matches = (modular_exponentiation(A, e1, p) == alice and
                   modular_exponentiation(B, e2, p) == bob)
    return dict(E1=E1, E2=E2, alice=alice, bob=bob, eve_matches=eve_matches)

def demo():
    alice, bob = make_parties()
    p = generate_prime(16); validate_modulus(p)
    print(f"Requested prime size: 16 bits\nModulus: generated using library prime generator"
          f"\nModulus bit length: {p.bit_length()}\nReceived modulus library validation: PASS")
    m1 = alice.initiate(p=p); m2 = bob.handle_init(m1)
    print("Alice initiation signature: VALID")
    m3 = alice.handle_response(m2); print("Bob response signature: VALID")
    bob.handle_finish(m3); print("Alice finish signature: VALID\nGenerator: validated")
    print("Transcript authenticated: YES")
    print("Shared-secret equality in local test:", "PASS" if alice.secret == bob.secret else "FAIL")
    print("Explicit key confirmation: NOT IMPLEMENTED")
    print(f"[classroom debug only] secret = {alice.secret}")
 
    print("\nEve vs unauthenticated DH (p=23, g=5)")
    print(eve_unauthenticated(), "Alice and Bob differ; Eve knows both")
    print("\nEve vs authenticated DH")
    alice, bob = make_parties(fixture=True)
    m2 = bob.handle_init(alice.initiate(p=23, g=5))
    print("Eve modified Bob's public value.")
    try:
        alice.handle_response(tamper(m2, "transcript", "B", value=17))
    except ProtocolError as e:
        print(f"Bob response signature: INVALID\nExchange aborted. ({e})")
 
    print("\nPerformance")
    print("| Bits | Trial | Prime generation (s) | Factorization (s) | Generator search (s) "
          "| Authenticated | Secrets match |")
    for bits in (16, 24, 32):
        for trial in (1, 2, 3):
            t0 = time.perf_counter(); p = generate_prime(bits); t1 = time.perf_counter()
            fs = prime_factors(p - 1); t2 = time.perf_counter()
            g = find_generator(p, fs); t3 = time.perf_counter()
            a, b = make_parties()
            try:
                run_exchange(a, b, p=p, g=g); auth = "Yes"
            except ProtocolError:
                auth = "No"
            print(f"| {bits} | {trial} | {t1-t0:.6f} | {t2-t1:.6f} | {t3-t2:.6f} "
                  f"| {auth} | {'Yes' if a.secret == b.secret else 'No'} |")

# tests ...

class TestMath(unittest.TestCase):
    
    def test_exponentiation(self):
    
        self.assertEqual(modular_exponentiation(5, 6, 23), 8)
    
        self.assertEqual(modular_exponentiation(5, 0, 23), 1)
    
        self.assertEqual(modular_exponentiation(5, 0, 1), 0)
    
        self.assertEqual(modular_exponentiation(-5, 3, 23), pow(-5, 3, 23))
    
        for _ in range(100):
    
            b = secrets.randbelow(10**6)
            
            e = secrets.randbelow(10**6)
            
            m = secrets.randbelow(10**6) + 1
            
            self.assertEqual(modular_exponentiation(b, e, m), pow(b, e, m))
    
        for bad in [(5, -1, 23), (5, 6, 0), (5.0, 2, 23), (5, True, 23), ("5", 2, 23)]:
    
            with self.assertRaises((ValueError, TypeError)):
    
                modular_exponentiation(*bad)
 
    def test_factors_generators(self):
       
        self.assertEqual(prime_factors(1), set())
       
        self.assertEqual(prime_factors(22), {2, 11})
       
        self.assertEqual(prime_factors(65536), {2})
       
        self.assertTrue(is_generator(5, 23, {2, 11}))
       
        self.assertFalse(is_generator(2, 23, {2, 11}))
       
        self.assertTrue(is_generator(3, 65537, {2}))
 
    def test_dh_fixture(self):
        
        A = modular_exponentiation(5, 6, 23)
        
        B = modular_exponentiation(5, 15, 23)
        
        self.assertEqual((A, B), (8, 19))
        
        self.assertEqual(modular_exponentiation(B, 6, 23), 2)
        
        self.assertEqual(modular_exponentiation(A, 15, 23), 2)
 
 
class TestPrimes(unittest.TestCase):
    
    def test_generation(self):
       
        for bits in (16, 24, 32):
          
            p = generate_prime(bits)
          
            self.assertEqual(p.bit_length(), bits)
          
            self.assertTrue(p % 2 == 1 and isPrime(p))
        
        for bad in (12, 33, True, 16.0, "16", None):
        
            with self.assertRaises(ValueError):
        
                generate_prime(bad)
 
    def test_received_modulus(self):
        
        for bad in (32769, "65521", 12345678901234, 23, True):
        
            with self.assertRaises(ProtocolError):
        
                validate_modulus(bad)
        
        validate_modulus(65521); validate_modulus(23, fixture=True)
 
 
class TestProtocol(unittest.TestCase):
    def setUp(self):
        
        self.a, self.b = make_parties(fixture=True)
        
        self.m1 = self.a.initiate(p=23, g=5)
 
    def rejects(self, f, *args):
        with self.assertRaises(ProtocolError):
            f(*args)
 
    def test_exchanges(self):
        a, b = make_parties(True); run_exchange(a, b, p=23, g=5)
        self.assertEqual(a.secret, b.secret)
        for bits in (16, 24, 32):
            for _ in range(3):
                a, b = make_parties(); run_exchange(a, b, bits=bits)
                self.assertEqual(a.secret, b.secret)
 
    def test_attacks_on_init(self):

        self.rejects(self.b.handle_init, tamper(self.m1, "A", value=10))
        
        self.rejects(self.b.handle_init, tamper(self.m1, "p", value=29))
        
        self.rejects(self.b.handle_init, tamper(self.m1, "g", value=2))
        
        self.rejects(self.b.handle_init, tamper(self.m1, "initiator", value="Eve"))
        
        self.rejects(self.b.handle_init, tamper(self.m1, "A", value="8"))  
        
        bad = json.loads(self.m1); bad["sig"] = "00" * 64
        
        self.rejects(self.b.handle_init, encode(bad))
        
        eve = Party("Alice", Ed25519PrivateKey.generate(), "Bob", None, True)
        
        self.rejects(self.b.handle_init, eve._send(json.loads(self.m1)["payload"]))
 
    def test_attacks_on_response(self):
        
        m2 = self.b.handle_init(self.m1)
        
        self.rejects(self.a.handle_response, tamper(m2, "transcript", "B", value=17))
 
    def test_replays_and_order(self):
        m2 = self.b.handle_init(self.m1)
        m3 = self.a.handle_response(m2)
        self.b.handle_finish(m3)

        # duplicate finish
        self.rejects(self.b.handle_finish, m3)                  
        
        # fresh alice session
        self.a.initiate(p=23, g=5)                              
        
        # old response
        self.rejects(self.a.handle_response, m2)                
        
        # fresh bob session
        self.b.handle_init(self.a.initiate(p=23, g=5))          
        
        # old finish
        self.rejects(self.b.handle_finish, m3)                  
        
        # wrong order
        self.rejects(make_parties(True)[1].handle_finish, m2)   
        
    def test_fresh_nonces(self):

        n = {json.loads(self.a.initiate(p=23, g=5))["payload"]["nonce_A"] for _ in range(5)}
        
        self.assertEqual(len(n), 5)
 
    def test_malformed(self):
        
        dup = b'{"payload":{},"payload":{},"sig":"aa"}'
        
        for raw in (b"not json", b"x" * 5000, dup, b'{"payload":{},"sig":"aa"}', "str", None):
            
            self.rejects(self.b.handle_init, raw)
 
    def test_eve_unauthenticated(self):
        
        r = eve_unauthenticated()
        
        self.assertEqual((r["E1"], r["E2"], r["alice"], r["bob"]), (10, 17, 6, 15))
        
        self.assertTrue(r["eve_matches"])
 
 
if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]], verbosity=2) if sys.argv[1:] == ["test"] else demo()
