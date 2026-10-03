from poly1305 import poly1305

key = bytes([0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
                 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b])
message = bytes.fromhex("43727970746f6772617068696320466f72756d2052657365617263682047726f7570")
result = poly1305(key, message)
print(f"Test 1: {result.hex()}")
assert result.hex() == "a8061dc1305136c6c22b8baf0c0127a9", "Test 1 failed"

key = bytes(32)
message = bytes(64)
result = poly1305(key, message)
print(f"Test 2: {result.hex()}")
assert result.hex() == "00000000000000000000000000000000", "Test 2 failed"

key = bytes.fromhex("0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e")
message = b"Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to"
result = poly1305(key, message)
print(f"Test 3: {result.hex()}")
assert result.hex() == "36e5f6b5c5e06070f0efca96227a863e", "Test 3 failed"

key = bytes.fromhex("36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000")
message = b"Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to"
result = poly1305(key, message)
print(f"Test 4: {result.hex()}")
assert result.hex() == "f3477e7cd95417af89a6b8794c310cf0", "Test 4 failed"

print("All Poly1305 tests passed!")
