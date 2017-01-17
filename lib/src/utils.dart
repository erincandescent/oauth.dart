library oauth.utils;

import 'dart:async';
import 'dart:io';
import 'dart:math';

Future get async =>
    new Future.delayed(const Duration(milliseconds: 0), () => null);

RandomAccessFile _randomFile;
bool _haveWarned = false;

List<int> getRandomBytes(int count) {
  if (!Platform.isWindows) {
    if (_randomFile == null) {
      _randomFile = new File("/dev/urandom").openSync();
    }

    return _randomFile.readSync(count);
  } else {
    var r = new Random.secure();
    return new List<int>.generate(count, (_) => r.nextInt(255),
        growable: false);
  }
}
