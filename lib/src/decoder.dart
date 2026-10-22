// Victron "Instant Readout" advertisement decoder. Victron devices broadcast
// encrypted manufacturer-data (company 0x02E1); given the per-device 16-byte key
// (copied from VictronConnect), each advert decrypts (AES-128-CTR) to a small
// bit-packed record. Layout + scaling recovered from libVictronConnect and the
// community victron-ble format.

import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// Bluetooth SIG company id for Victron Energy BV.
const int kVictronCompanyId = 0x02E1;

// Record types (manufacturer-data byte 3).
const int recSolarCharger = 0x01;
const int recBatteryMonitor = 0x02;
const int recSmartLithium = 0x05;
const int recOrionXs = 0x0D;

/// A decoded Victron advertisement in brand-neutral terms. Any field may be null
/// when the device reports "not available" for it.
class VictronReading {
  final int recordType;
  final double? voltage; // V
  final double? current; // A (+ charge / - discharge, per Victron sign)
  final int? soc; // %
  final double? temperatureC;
  final List<double> cells; // SmartLithium cell voltages
  final double? consumedAh;
  final int? timeToGoMinutes;
  final int? alarm;

  const VictronReading({
    required this.recordType,
    this.voltage,
    this.current,
    this.soc,
    this.temperatureC,
    this.cells = const [],
    this.consumedAh,
    this.timeToGoMinutes,
    this.alarm,
  });
}

class VictronDecoder {
  /// 16-byte per-device AES key.
  final Uint8List key;

  VictronDecoder(this.key) {
    if (key.length != 16) throw ArgumentError('Victron key must be 16 bytes');
  }

  factory VictronDecoder.fromHex(String hex) {
    final clean = hex.replaceAll(RegExp(r'[^0-9a-fA-F]'), '');
    if (clean.length != 32) throw ArgumentError('Victron key must be 32 hex characters');
    return VictronDecoder(Uint8List.fromList(
        [for (var i = 0; i < 32; i += 2) int.parse(clean.substring(i, i + 2), radix: 16)]));
  }

  /// Decode one advertisement's manufacturer-data payload (with the 0x02E1
  /// company id already stripped). Returns null if it isn't a decodable Victron
  /// instant-readout record or the key doesn't match.
  VictronReading? decode(List<int> m) {
    if (m.length < 8 || m[0] != 0x10) return null;
    final recordType = m[3];
    final iv = m[4] | (m[5] << 8);
    if (m[6] != key[0]) return null; // key-check byte
    final plain = ctrCrypt(m.sublist(7), iv);
    return parseRecord(recordType, plain);
  }

  /// AES-128-CTR over [data] with the 16-bit [iv] in the low two counter bytes.
  /// Victron records fit a single keystream block (<= 16 bytes). XOR is
  /// symmetric, so this both encrypts and decrypts.
  Uint8List ctrCrypt(List<int> data, int iv) {
    final counter = Uint8List(16);
    counter[0] = iv & 0xFF;
    counter[1] = (iv >> 8) & 0xFF;
    final engine = AESEngine()..init(true, KeyParameter(key));
    final keystream = Uint8List(16);
    engine.processBlock(counter, 0, keystream, 0);
    final out = Uint8List(data.length);
    for (var i = 0; i < data.length; i++) {
      out[i] = data[i] ^ keystream[i];
    }
    return out;
  }

  /// Parse a decrypted record body by type.
  static VictronReading? parseRecord(int type, List<int> p) {
    final b = _Bits(p);
    switch (type) {
      case recSmartLithium:
        b.read(32); // BMS flags
        b.read(16); // error/status
        final cells = <double>[];
        for (var i = 0; i < 8; i++) {
          final raw = b.read(7);
          if (raw != 0x7F) cells.add(2.60 + raw * 0.01);
        }
        final vRaw = b.read(12);
        b.read(4); // balancer status
        final tRaw = b.read(7);
        return VictronReading(
          recordType: type,
          voltage: vRaw == 0xFFF ? null : vRaw * 0.01,
          temperatureC: tRaw == 0x7F ? null : (tRaw - 40).toDouble(),
          cells: cells,
        );
      case recBatteryMonitor:
        final ttg = b.read(16);
        final vRaw = b.readSigned(16);
        final alarm = b.read(16);
        b.read(16); // aux value
        b.read(2); // aux type
        final iRaw = b.readSigned(22);
        final consumed = b.read(20);
        final soc = b.read(10);
        return VictronReading(
          recordType: type,
          voltage: vRaw == 0x7FFF ? null : vRaw * 0.01,
          current: iRaw == 0x1FFFFF ? null : iRaw * 0.001,
          soc: soc == 0x3FF ? null : (soc / 10).round(),
          consumedAh: consumed == 0xFFFFF ? null : consumed * 0.1,
          timeToGoMinutes: ttg == 0xFFFF ? null : ttg,
          alarm: alarm,
        );
      default:
        return VictronReading(recordType: type);
    }
  }
}

/// LSB-first bit reader over a byte list.
class _Bits {
  final List<int> data;
  int _pos = 0;
  _Bits(this.data);

  int read(int n) {
    var v = 0;
    for (var i = 0; i < n; i++) {
      final byte = _pos ~/ 8;
      final bit = _pos % 8;
      if (byte < data.length && (data[byte] & (1 << bit)) != 0) v |= 1 << i;
      _pos++;
    }
    return v;
  }

  int readSigned(int n) {
    final v = read(n);
    return v >= (1 << (n - 1)) ? v - (1 << n) : v;
  }
}
