import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:victron_ble/victron_ble.dart';

/// LSB-first bit writer, mirroring the decoder's reader.
class _BitWriter {
  final List<int> _bytes = [];
  int _cur = 0;
  int _bit = 0;
  void write(int value, int n) {
    for (var i = 0; i < n; i++) {
      if ((value >> i) & 1 != 0) _cur |= 1 << _bit;
      if (++_bit == 8) {
        _bytes.add(_cur);
        _cur = 0;
        _bit = 0;
      }
    }
  }

  Uint8List finish() {
    if (_bit > 0) _bytes.add(_cur);
    return Uint8List.fromList(_bytes);
  }
}

final _key = Uint8List.fromList(List.generate(16, (i) => i + 1)); // 01 02 .. 10

void main() {
  test('SmartLithium round-trip through AES-128-CTR', () {
    final w = _BitWriter()
      ..write(0, 32) // BMS flags
      ..write(0, 16) // error
      ..write(70, 7) // cell 1 -> 3.30 V
      ..write(71, 7); // cell 2 -> 3.31 V
    for (var i = 0; i < 6; i++) {
      w.write(0x7F, 7); // cells 3-8 n/a
    }
    w
      ..write(1280, 12) // 12.80 V
      ..write(0, 4) // balancer
      ..write(65, 7); // 25 C
    final plain = w.finish();

    final dec = VictronDecoder(_key);
    const iv = 0x1234;
    final ct = dec.ctrCrypt(plain, iv);
    final m = [0x10, 0xA4, 0xA3, recSmartLithium, iv & 0xFF, iv >> 8, _key[0], ...ct];

    final r = dec.decode(m)!;
    expect(r.recordType, recSmartLithium);
    expect(r.voltage, closeTo(12.80, 1e-6));
    expect(r.temperatureC, closeTo(25.0, 1e-6));
    expect(r.cells.length, 2);
    expect(r.cells[0], closeTo(3.30, 1e-6));
    expect(r.cells[1], closeTo(3.31, 1e-6));
  });

  test('BatteryMonitor field decode', () {
    final w = _BitWriter()
      ..write(600, 16) // time-to-go 600 min
      ..write(1325, 16) // 13.25 V
      ..write(0, 16) // alarm
      ..write(0, 16) // aux
      ..write(0, 2) // aux type
      ..write(5000, 22) // 5.0 A
      ..write(100, 20) // consumed 10.0 Ah
      ..write(750, 10); // SOC 75.0 %
    final r = VictronDecoder.parseRecord(recBatteryMonitor, w.finish())!;
    expect(r.voltage, closeTo(13.25, 1e-6));
    expect(r.current, closeTo(5.0, 1e-6));
    expect(r.soc, 75);
    expect(r.consumedAh, closeTo(10.0, 1e-6));
    expect(r.timeToGoMinutes, 600);
  });

  test('wrong key is rejected by the key-check byte', () {
    final dec = VictronDecoder(_key);
    final m = [0x10, 0, 0, recSmartLithium, 0, 0, 0x99 /* != key[0] */, 1, 2, 3];
    expect(dec.decode(m), isNull);
  });

  test('fromHex parses a 32-char key', () {
    final d = VictronDecoder.fromHex('0102030405060708090a0b0c0d0e0f10');
    expect(d.key[0], 0x01);
    expect(d.key[15], 0x10);
  });
}
