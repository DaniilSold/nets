# PCAP фикстуры

* `arp_spoof.pcap` — симулированный ARP spoof (создать через `tools/traffic_gen.py --capture arp`).
* `dns_nx.pcap` — всплеск NXDOMAIN.
* `smb_scan.pcap` — SMB широковещание/сканирование.

Файлы хранятся офлайн и могут быть сгенерированы командой:
```
python3 tools/traffic_gen.py --scenario <name> --capture tests/pcap/<file>.pcap
```
