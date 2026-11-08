import 'dart:math';
import 'dart:typed_data';

import 'package:coconut_vault/services/secure_zone/secure_zone_keystore.dart';
import 'package:pointycastle/export.dart';

/// Stand-in for the platform keystore on Linux desktop demo builds, which have
/// no secure hardware module. Keys live in this process's memory only, so
/// anything encrypted with them is unreadable after a restart. Not a secure
/// keystore: demo builds only.
class DesktopDemoKeystore extends SecureZoneKeystore {
  final Map<String, Uint8List> _keys = {};
  final Random _random = Random.secure();

  Uint8List _randomBytes(int length) => Uint8List.fromList(List.generate(length, (_) => _random.nextInt(256)));

  GCMBlockCipher _cipher(bool forEncryption, String alias, Uint8List iv) {
    final key = _keys[alias];
    if (key == null) throw StateError('No key for $alias');
    return GCMBlockCipher(AESEngine())..init(forEncryption, AEADParameters(KeyParameter(key), 128, iv, Uint8List(0)));
  }

  @override
  Future<void> generateKey({required String alias, bool userAuthRequired = false, bool perUseAuth = false}) async {
    _keys[alias] = _randomBytes(32);
  }

  @override
  Future<void> deleteKey({required String alias}) async {
    _keys.remove(alias);
  }

  @override
  Future<List<String>> deleteKeys({required List<String> aliasList}) async {
    return [
      for (final alias in aliasList)
        if (_keys.remove(alias) != null) alias,
    ];
  }

  @override
  Future<Map<String, dynamic>> encrypt({required String alias, required Uint8List plaintext}) async {
    final iv = _randomBytes(12);
    return {'ciphertext': _cipher(true, alias, iv).process(plaintext), 'iv': iv, 'usedStrongBox': false};
  }

  @override
  Future<Uint8List?> decrypt({
    required String alias,
    required Uint8List ciphertext,
    required Uint8List iv,
    bool autoAuth = true,
  }) async {
    return _cipher(false, alias, iv).process(ciphertext);
  }
}
