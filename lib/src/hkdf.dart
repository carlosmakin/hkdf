import 'dart:typed_data';
import 'package:crypto/crypto.dart';

/// HMAC-based Key Derivation Function (HKDF) (RFC 5869).
///
/// HKDF is a symmetric key derivation mechanism that transforms weaker input key material (IKM) into
/// cryptographically strong keys. It's essential in scenarios where secure and robust key generation
/// is necessary from potentially less secure initial keys, applicable across various cryptographic applications.
abstract class HKDF {
  /// Extracts a fixed-length pseudorandom key from the input key material (IKM) using an optional salt.
  ///
  /// The salt (a non-secret random value) is recommended to be at least as long as the hash output
  /// to provide cryptographic strength against attacks on weak IKM. The use of salt adds strength against
  /// rainbow table attacks. The input key material must not be empty.
  static Uint8List extract(Hash hash, Uint8List ikm, [Uint8List? salt]) {
    if (ikm.isEmpty) throw ArgumentError('IKM must not be empty');
    final Hmac hmac = Hmac(hash, salt ?? Uint8List(hash.blockSize));
    return Uint8List.fromList(hmac.convert(ikm).bytes);
  }

  /// Expands the pseudorandom key (PRK) to the desired length using optional context-specific info.
  ///
  /// The 'info' parameter is optional context and application-specific information used to bind the
  /// derived key material to a specific context or to achieve domain separation. This allows the
  /// derived keys to be independent and functionally separate in different usage scenarios.
  /// The length of the output key material must not exceed 255 times the hash length.
  static Uint8List expand(Hash hash, Uint8List prk, int length, [Uint8List? info]) {
    final int hashLen = _getHashLength(hash);
    if (prk.length < hashLen) throw ArgumentError('PRK length must match or exceed hash length');
    if (length > 255 * hashLen) throw ArgumentError('Requested length exceeds maximum length');

    final BytesBuilder output = BytesBuilder();
    final Hmac hmac = Hmac(hash, prk);
    List<int> t = <int>[];
    for (int i = 1; output.length < length; i++) {
      t = hmac.convert(<int>[...t, if (info != null) ...info, i]).bytes;
      output.add(t);
    }
    return output.takeBytes().sublist(0, length);
  }
}

/// Helper function to determine the hash output length based on hash algorithm.
int _getHashLength(Hash hashAlgorithm) {
  return switch (hashAlgorithm) {
    sha1 => 20,
    sha224 => 28,
    sha256 => 32,
    sha384 => 48,
    sha512 => 64,
    sha512224 => 28,
    sha512256 => 32,
    md5 => 16,
    _ => throw ArgumentError('Unsupported hash algorithm')
  };
}
