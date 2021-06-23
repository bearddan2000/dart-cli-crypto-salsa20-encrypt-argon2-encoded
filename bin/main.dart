import 'package:dargon2/dargon2.dart';
import 'package:encrypt/encrypt.dart';

final s = Salt.newSalt();
final key = Key.fromLength(32);
final iv = IV.fromLength(8);

encrypt(psw) {
  final encrypter = Encrypter(Salsa20(key));
  final encrypted = encrypter.encrypt(psw, iv: iv);
  return encrypted.base64;
}

Future<bool> verify(psw1, psw2, hashed) async {
  print("[VERIFY] $psw1\t$psw2");
  psw1 = encrypt(psw1);
  try {
   await argon2.verifyHashString(psw1, hashed);
   return true;
   } on Exception {
    return false;
   }
}

Future<String> hash(psw) async {
  print("[HASH] plainPassword: $psw");
  psw = encrypt(psw);
  var result = await argon2.hashPasswordString(psw, salt: s);
  String hashed = result.encodedString;
  print("[HASH] hashedPassword: $hashed");
  return hashed;
}

main() async {
  String psw1 = "pass1234";
  String psw2 = "1234pass";
  String hash1 = await hash(psw1);
  String hash2 = await hash(psw2);
  bool first = await verify(psw1, psw2, hash2);
  print("[VERIFY] $first");
  bool second = await verify(psw1, psw1, hash1);
  print("[VERIFY] $second");
}
