# План тестирования NETS

## Стратегия
| Тип теста | Цель | Инструменты |
| --- | --- | --- |
| Юнит | Проверка парсеров (DNS, ARP), DSL движка, сериализации БД | `cargo test`, mock fixtures |
| Интеграция | Путь Collector→Analyzer→Storage | `cargo test --test e2e`, network namespaces, PowerShell | 
| Нагрузочные | Проверка деградации до flow-счётчиков, профилирование CPU/RAM | `tools/loadgen.py`, `perf`, `packetmon` |
| Безопасность | Валидация отказоустойчивости, DoS на ring-buffer | `tools/arp_spoof.py`, fuzzed pcap |

## Матрица требований
| Требование | Тест(ы) |
| --- | --- |
| RAM ≤ 40 МБ | `tests/perf_memory.sh` |
| CPU ≤ 5% | `tests/perf_cpu.sh` |
| 4/4 аномалии | `tests/anomaly_scenarios.sh` |
| Нет исходящих соединений | `tests/self_guard.sh` |
| Карантин с откатом | `tests/quarantine.ps1`, `tests/quarantine.sh` |

## Автоматизация
* `tests/anomaly_scenarios.sh` — запускает namespaces, генерирует трафик (web listener, ARP spoof, DNS NXDOMAIN, SMB scan).
* `tests/quarantine.ps1` — на Windows создаёт временный listener, применяет WFP правило, проверяет откат.
* `tests/perf_memory.sh` — использует `/usr/bin/time -v` и нагрузочный скрипт.

## Скрипты генерации
### Linux (bash + scapy)
```bash
#!/usr/bin/env bash
set -euo pipefail
nsenter --net=/var/run/netns/test -- python3 tools/traffic_gen.py --scenario dns-nx-spike
```

### PowerShell (Windows)
```powershell
$ErrorActionPreference = "Stop"
Start-Process -FilePath python -ArgumentList "-m http.server 8080" -PassThru | Set-Variable server
Start-Sleep -Seconds 5
# validation via CLI
nets-cli --config C:\nets\config.toml flows --limit 5
Stop-Process -Id $server.Id
```

## PCAP фикстуры
* `tests/pcap/arp_spoof.pcap` — ARP Poisoning.
* `tests/pcap/dns_nx.pcap` — всплеск NXDOMAIN.
* `tests/pcap/smb_scan.pcap` — многопортовое сканирование 445/139.

## Отчётность
* После каждого прогона `tests/report.py` собирает JSON и формирует HTML/PDF через WeasyPrint (офлайн).
* Метрики ложных срабатываний: количество алертов/сценарий, требуется ≤ 1 ложного за 24 часа после бейзлайна.

## DoD чек-лист
- [ ] RAM профилирование выполнено.
- [ ] CPU профилирование выполнено.
- [ ] Сценарии аномалий подтверждены.
- [ ] Карантин и откат проверены.
- [ ] Self-check отсутствия исходящих подключений активен.
