/// Victron "Instant Readout" advertisement decoder: given a device's 16-byte
/// key (from VictronConnect), decrypt and parse its encrypted BLE broadcasts
/// (AES-128-CTR) into brand-neutral battery readings. Passive — no connection.
library;

export 'src/decoder.dart';
