# Windows-специфичные возможности мониторинга

## Обзор

Приложение предоставляет расширенные возможности мониторинга сетевой активности на Windows 10/11 с использованием нативных Windows API.

## Основные модули

### 1. Process Information Collector
**Модуль:** `app/collector/src/windows/process_info.rs`

Собирает детальную информацию о процессах с использованием Windows API:

- **PID и PPID** - идентификаторы процесса и родительского процесса
- **Имя процесса** - через CreateToolhelp32Snapshot
- **Полный путь к исполняемому файлу** - через QueryFullProcessImageNameW
- **SHA-256 хэш** (первые 16 символов) - вычисляется для бинарного файла
- **Информация о пользователе** - через OpenProcessToken и GetTokenInformation
- **Статус цифровой подписи** - проверка через GetFileVersionInfoW

#### Использование:
```rust
use collector::windows::ProcessInfoCollector;

let info = ProcessInfoCollector::get_process_info(1234);
if let Some(process) = info {
    println!("Process: {}", process.name.unwrap_or_default());
    println!("Path: {}", process.exe_path.unwrap_or_default());
    println!("SHA-256: {}", process.sha256_16.unwrap_or_default());
    println!("Signed: {}", process.signed.unwrap_or(false));
}
```

### 2. Network Monitor
**Модуль:** `app/collector/src/windows/network_monitor.rs`

Использует IP Helper API для сбора информации о сетевых соединениях:

- **TCP соединения (IPv4/IPv6)** - через GetExtendedTcpTable
- **UDP endpoints (IPv4/IPv6)** - через GetExtendedUdpTable
- **Привязка к процессам** - каждое соединение связано с PID
- **Состояние TCP** - LISTEN, ESTABLISHED, TIME_WAIT и др.
- **5-tuple** - источник/назначение IP:Port + протокол

#### Функции:
- `collect_tcp_connections()` - все TCP соединения
- `collect_udp_endpoints()` - все UDP endpoints
- Автоматическое определение направления (Inbound/Outbound/Lateral)

### 3. Protocol Detector
**Модуль:** `app/collector/src/windows/protocol_detector.rs`

Детектирует локальные протоколы и службы:

#### Поддерживаемые протоколы:
- **mDNS** (порт 5353, 224.0.0.251, ff02::fb) - Multicast DNS
- **LLMNR** (порт 5355, 224.0.0.252, ff02::1:3) - Link-Local Multicast Name Resolution
- **NetBIOS-NS** (порт 137) - NetBIOS Name Service
- **NetBIOS-DGM** (порт 138) - NetBIOS Datagram Service
- **NetBIOS-SSN** (порт 139) - NetBIOS Session Service
- **SSDP** (порт 1900, 239.255.255.250) - Simple Service Discovery Protocol
- **DHCP** (порты 67/68) - Dynamic Host Configuration Protocol
- **DNS** (порт 53) - Domain Name System
- **SMB** (порт 445) - Server Message Block
- **RDP** (порт 3389) - Remote Desktop Protocol
- **Kerberos** (порт 88) - Аутентификация Active Directory
- **LDAP/LDAPS** (порты 389/636) - Directory Services

#### Использование:
```rust
use collector::windows::{ProtocolDetector, LocalProtocol};

if let Some(proto) = ProtocolDetector::detect_protocol(&flow) {
    match proto {
        LocalProtocol::MDNS => println!("mDNS activity detected"),
        LocalProtocol::SMB => println!("SMB file sharing"),
        _ => {}
    }
}
```

### 4. Anomaly Detector
**Модуль:** `app/collector/src/windows/anomaly_detector.rs`

Обнаруживает подозрительную сетевую активность:

#### Типы аномалий:
1. **Hidden Listener** - скрытые слушающие сервисы
   - Неподписанные процессы на системных портах (<1024)
   - Процессы вне системных директорий

2. **Port Scanning** - сканирование портов
   - Более 10 уникальных портов за 60 секунд

3. **Lateral Movement** - боковое перемещение
   - SMB/RDP/LDAP соединения в локальной сети

4. **Suspicious DNS** - аномальный DNS
   - Высокая частота неудачных запросов (>80%)
   - DGA-подобные домены (высокая энтропия)

5. **Local Proxy** - локальные прокси/туннели
   - Неизвестные процессы на портах 8080, 8888, 3128, 1080, 9050

6. **ARP Spoofing** - подмена ARP
   - Изменение MAC-адреса для существующего IP

#### Использование:
```rust
use collector::windows::AnomalyDetector;

let detector = AnomalyDetector::new();
let anomalies = detector.analyze_flow(&flow);

for anomaly in anomalies {
    match anomaly {
        Anomaly::HiddenListener { pid, port, .. } => {
            println!("Hidden listener detected: PID {} on port {}", pid, port);
        }
        Anomaly::PortScanning { src_ip, port_count, .. } => {
            println!("Port scan from {}: {} ports", src_ip, port_count);
        }
        _ => {}
    }
}
```

### 5. Action Handler
**Модуль:** `app/collector/src/windows/actions.rs`

Управление процессами и сетевыми соединениями:

#### Функции:
- **terminate_process(pid)** - завершение процесса
- **block_connection(...)** - блокировка соединения через Windows Firewall
- **quarantine_process(pid)** - карантин процесса (блокировка всех соединений)
- **list_blocked_connections()** - список заблокированных соединений

#### Использование:
```rust
use collector::windows::ActionHandler;

// Завершить процесс
ActionHandler::terminate_process(1234)?;

// Заблокировать соединение
ActionHandler::block_connection(
    "192.168.1.100", 49152,
    "8.8.8.8", 443,
    "TCP"
)?;

// Поместить процесс в карантин
ActionHandler::quarantine_process(1234)?;
```

## Требования

### Системные требования:
- Windows 10 (версия 1809+) или Windows 11
- x64 архитектура
- Права администратора для некоторых функций

### Привилегии:
Для полной функциональности требуются права администратора:
- Чтение информации о процессах
- Создание правил Windows Firewall
- Завершение процессов
- Доступ к расширенным TCP/UDP таблицам

### API и зависимости:
- Windows API через crate `windows` v0.52
- IP Helper API (iphlpapi.dll)
- Process Status API (psapi.dll)
- Windows Firewall (через netsh или WFP)

## Архитектура

### Поток данных:
```
Windows API (IP Helper, PSAPI)
    ↓
NetworkMonitor (TCP/UDP таблицы)
    ↓
ProcessInfoCollector (информация о процессах)
    ↓
ProtocolDetector (идентификация протокола)
    ↓
AnomalyDetector (анализ аномалий)
    ↓
FlowEvent (обогащенное событие)
    ↓
UI / Storage / Alerts
```

### Периодический сбор:
- Каждые 2 секунды собираются данные о соединениях
- Информация о процессах получается по требованию
- Кэширование результатов для производительности

## Производительность

### Оптимизации:
- Использование IP Helper API вместо парсинга netstat
- Batch-обработка соединений
- Кэширование информации о процессах
- Минимальная нагрузка на систему (<5% CPU, <40 МБ RAM)

### Ограничения:
- Максимум 2000 потоков в памяти
- Дедупликация соединений по 5-tuple
- Throttling при высокой нагрузке

## Безопасность

### Защита данных:
- Локальное хранение без передачи в сеть
- Шифрование SQLite базы данных (AES-GCM)
- Контроль доступа к конфигурации

### Проверки:
- Валидация цифровых подписей процессов
- Верификация хэшей исполняемых файлов
- Контроль целостности данных

## UI Components

### FlowDetails
Детальное отображение информации о потоке:
- Сетевая информация (5-tuple, состояние, метрики)
- Информация о процессе (путь, хэш, подпись, пользователь)
- TLS метаданные (SNI, ALPN, JA3)
- DNS данные (QNAME, QTYPE, RCODE)
- Layer 2 информация (ARP/ND)
- Действия (блокировка, завершение процесса)

### LocalProtocolsView
Визуализация локальных протоколов:
- Статистика по каждому протоколу
- Количество вхождений
- Связанные процессы
- Описания протоколов

## Интеграция с Tauri

### Команды:
```typescript
// Завершить процесс
await invoke('terminate_process', { pid: 1234 });

// Заблокировать соединение
await invoke('block_connection', {
  srcIp: '192.168.1.100',
  srcPort: 49152,
  dstIp: '8.8.8.8',
  dstPort: 443,
  protocol: 'TCP'
});

// Карантин процесса
await invoke('quarantine_process', { pid: 1234 });

// Список блокировок
const blocked = await invoke('list_blocked_connections');
```

## Расширение функциональности

### Добавление новых протоколов:
1. Добавить константу порта в `ProtocolDetector`
2. Добавить enum вариант в `LocalProtocol`
3. Добавить логику детекции в `detect_protocol()`
4. Добавить описание в локализацию

### Добавление новых аномалий:
1. Добавить вариант в `Anomaly` enum
2. Реализовать логику детекции в `AnomalyDetector`
3. Добавить обработку в UI

## Известные ограничения

1. **ETW интеграция** - в текущей версии используется IP Helper API вместо ETW
2. **WFP драйвер** - блокировка через netsh вместо нативного WFP callout
3. **TLS inspection** - только метаданные из ClientHello, без расшифровки
4. **Layer 2** - ограниченная поддержка ARP/ND событий

## Планы развития

1. Полная интеграция с ETW (Microsoft-Windows-TCPIP provider)
2. Разработка WFP callout драйвера для точного контроля
3. Расширенный DNS-анализ (DoH, DoT детекция)
4. Интеграция с Windows Defender ATP
5. Автоматический анализ JA3/JA3S хэшей
6. Machine Learning для детекции аномалий

## Тестирование

### Запуск тестов:
```bash
# Все тесты
cargo test --package collector

# Только Windows-тесты
cargo test --package collector --target x86_64-pc-windows-msvc

# С выводом
cargo test --package collector -- --nocapture
```

### Integration тесты:
Требуют прав администратора:
```powershell
# Запуск от администратора
cargo test --package collector --test integration -- --ignored
```

## Troubleshooting

### Проблема: "Access Denied" при получении информации о процессе
**Решение:** Запустите приложение от имени администратора

### Проблема: Не удается создать firewall правило
**Решение:** Проверьте, что Windows Firewall Service запущен:
```powershell
Get-Service -Name mpssvc
Start-Service mpssvc
```

### Проблема: Высокое потребление CPU
**Решение:** Увеличьте интервал сбора данных в конфигурации

## Ссылки

- [Windows IP Helper API](https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/)
- [Windows Filtering Platform](https://docs.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page)
- [ETW Provider Reference](https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
