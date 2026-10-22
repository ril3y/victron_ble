# victron_ble

Victron **Instant Readout** advertisement decoder.

Victron devices broadcast encrypted manufacturer-data (company `0x02E1`). Given
the per-device 16-byte key (copied from VictronConnect: Settings -> Product info
-> Encryption key), each advert decrypts (**AES-128-CTR**) to a small bit-packed
record. This package decodes SmartLithium (cells, voltage, temperature) and
BatteryMonitor / SmartShunt (voltage, current, SOC, consumed Ah, time-to-go)
records into brand-neutral readings. Passive — no connection or pairing needed.

Format recovered by static analysis for interoperability; not affiliated with
Victron Energy.

## License

MIT.
