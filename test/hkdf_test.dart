import 'package:hkdf/src/hkdf.dart';
import 'package:test/test.dart';
import 'package:crypto/crypto.dart';
import 'dart:typed_data';

typedef HKDFTestVector = Map<String, dynamic>;

void main() {
  group('HKDF RFC 5869', () {
    for (int i = 0; i < hkdfTestVectors.length; i++) {
      final HKDFTestVector testVector = hkdfTestVectors[i];
      test('${testVector['desc']} ${(i + 1)}', () {
        final Hash hash = testVector['hash'];
        final Uint8List ikm = parseBlockHexString(testVector['ikm'])!;
        final Uint8List? salt = parseBlockHexString(testVector['salt']);
        final Uint8List info = parseBlockHexString(testVector['info'])!;
        final int length = testVector['length']!;

        final Uint8List expectedPrk = parseBlockHexString(testVector['prk'])!;
        final Uint8List expectedOkm = parseBlockHexString(testVector['okm'])!;

        final Uint8List prk = HKDF.extract(hash, ikm, salt);
        final Uint8List okm = HKDF.expand(hash, prk, length, info);

        expect(prk, equals(expectedPrk));
        expect(okm, equals(expectedOkm));
      });
    }
  });
}

const List<HKDFTestVector> hkdfTestVectors = <HKDFTestVector>[
  // Test Vector #1
  <String, dynamic>{
    'desc': 'Basic test case with SHA-256',
    'hash': sha256,
    'ikm': '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
    'salt': '000102030405060708090a0b0c',
    'info': 'f0f1f2f3f4f5f6f7f8f9',
    'length': 42,
    'prk': '''
      077709362c2e32df0ddc3f0dc47bba63
      90b6c73bb50f9c3122ec844ad7c2b3e5
      ''',
    'okm': '''
      3cb25f25faacd57a90434f64d0362f2a
      2d2d0a90cf1a5a4c5db02d56ecc4c5bf
      34007208d5b887185865
      ''',
  },
  // Test Vector #2
  <String, dynamic>{
    'desc': 'Test with SHA-256 and longer inputs/outputs',
    'hash': sha256,
    'ikm': '''
      000102030405060708090a0b0c0d0e0f
      101112131415161718191a1b1c1d1e1f
      202122232425262728292a2b2c2d2e2f
      303132333435363738393a3b3c3d3e3f
      404142434445464748494a4b4c4d4e4f
      ''',
    'salt': '''
      606162636465666768696a6b6c6d6e6f
      707172737475767778797a7b7c7d7e7f
      808182838485868788898a8b8c8d8e8f
      909192939495969798999a9b9c9d9e9f
      a0a1a2a3a4a5a6a7a8a9aaabacadaeaf
      ''',
    'info': '''
      b0b1b2b3b4b5b6b7b8b9babbbcbdbebf
      c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
      d0d1d2d3d4d5d6d7d8d9dadbdcdddedf
      e0e1e2e3e4e5e6e7e8e9eaebecedeeef
      f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
      ''',
    'length': 82,
    'prk': '''
      06a6b88c5853361a06104c9ceb35b45c
      ef760014904671014a193f40c15fc244
      ''',
    'okm': '''
      b11e398dc80327a1c8e7f78c596a4934
      4f012eda2d4efad8a050cc4c19afa97c
      59045a99cac7827271cb41c65e590e09
      da3275600c2f09b8367793a9aca3db71
      cc30c58179ec3e87c14c01d5c1f3434f
      1d87
      ''',
  },
  // Test Vector #3
  <String, dynamic>{
    'desc': 'Test with SHA-256 and zero-length salt/info',
    'hash': sha256,
    'ikm': '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
    'salt': '',
    'info': '',
    'length': 42,
    'prk': '''
      19ef24a32c717b167f33a91d6f648bdf
      96596776afdb6377ac434c1c293ccb04
      ''',
    'okm': '''
      8da4e775a563c18f715f802a063c5a31
      b8a11f5c5ee1879ec3454e5f3c738d2d
      9d201395faa4b61a96c8
      ''',
  },
  // Test Vector #4
  <String, dynamic>{
    'desc': 'Basic test case with SHA-1',
    'hash': sha1,
    'ikm': '0b0b0b0b0b0b0b0b0b0b0b',
    'salt': '000102030405060708090a0b0c',
    'info': 'f0f1f2f3f4f5f6f7f8f9',
    'length': 42,
    'prk': '9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243',
    'okm': '''
      085a01ea1b10f36933068b56efa5ad81
      a4f14b822f5b091568a9cdd4f155fda2
      c22e422478d305f3f896
      ''',
  },
  // Test Vector #5
  <String, dynamic>{
    'desc': 'Test with SHA-1 and longer inputs/outputs',
    'hash': sha1,
    'ikm': '''
      000102030405060708090a0b0c0d0e0f
      101112131415161718191a1b1c1d1e1f
      202122232425262728292a2b2c2d2e2f
      303132333435363738393a3b3c3d3e3f
      404142434445464748494a4b4c4d4e4f
      ''',
    'salt': '''
      606162636465666768696a6b6c6d6e6f
      707172737475767778797a7b7c7d7e7f
      808182838485868788898a8b8c8d8e8f
      909192939495969798999a9b9c9d9e9f
      a0a1a2a3a4a5a6a7a8a9aaabacadaeaf
      ''',
    'info': '''
      b0b1b2b3b4b5b6b7b8b9babbbcbdbebf
      c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
      d0d1d2d3d4d5d6d7d8d9dadbdcdddedf
      e0e1e2e3e4e5e6e7e8e9eaebecedeeef
      f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
      ''',
    'length': 82,
    'prk': '8adae09a2a307059478d309b26c4115a224cfaf6',
    'okm': '''
      0bd770a74d1160f7c9f12cd5912a06eb
      ff6adcae899d92191fe4305673ba2ffe
      8fa3f1a4e5ad79f3f334b3b202b2173c
      486ea37ce3d397ed034c7f9dfeb15c5e
      927336d0441f4c4300e2cff0d0900b52
      d3b4
      ''',
  },
  // Test Vector #6
  <String, dynamic>{
    'desc': 'Test with SHA-1 and zero-length salt/info',
    'hash': sha1,
    'ikm': '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
    'salt': '',
    'info': '',
    'length': 42,
    'prk': 'da8c8a73c7fa77288ec6f5e7c297786aa0d32d01',
    'okm': '''
      0ac1af7002b3d761d1e55298da9d0506
      b9ae52057220a306e07b6b87e8df21d0
      ea00033de03984d34918
      ''',
  },
  // Test Vector #7
  <String, dynamic>{
    'desc': 'Test with SHA-1, salt not provided (zero octets), zero-length info',
    'hash': sha1,
    'ikm': '0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c',
    'salt': null,
    'info': '',
    'length': 42,
    'prk': '2adccada18779e7c2077ad2eb19d3f3e731385dd',
    'okm': '''
      2c91117204d745f3500d636a62f64f0a
      b3bae548aa53d423b0d1f27ebba6f5e5
      673a081d70cce7acfc48
      ''',
  },
];

Uint8List? parseBlockHexString(String? hexString) {
  if (hexString == null) return null;
  final String continuousHex = hexString.replaceAll(RegExp(r'\s+'), '');
  final List<String> hexBytes = <String>[];
  for (int i = 0; i < continuousHex.length; i += 2) {
    hexBytes.add(continuousHex.substring(i, i + 2));
  }
  return Uint8List.fromList(
    hexBytes.map((String byte) => int.parse(byte, radix: 16)).toList(),
  );
}
