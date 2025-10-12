# NETS — Локальный мониторинг сетевых потоков

## Обзор
NETS (Network Telemetry Sentinel) — кроссплатформенное офлайн-приложение для мониторинга локальных сетевых потоков уровня L2–L4 с точной привязкой к процессам и автономным обнаружением аномалий.

## Репозиторий
```
app/
  collector/    # eBPF/ETW сбор метаданных
  normalizer/   # Оконная агрегация и унификация
  analyzer/     # Бейзлайн, DSL правила, алерты
  policy/       # Карантин и локальные реакции
  storage/      # Шифрованное SQLite хранилище
  ui/           # Desktop UI (Tauri + React offline shell)
  cli/          # Административный CLI
config/         # Шаблоны конфигураций
rules/          # Примеры правил DSL
pkg/            # Скрипты сборки офлайн-пакетов
scripts/        # Пакетирование (.deb/.rpm/.msi/.dmg)
tools/          # Генераторы трафика
tests/          # План и автоматизация тестов
docs/           # Архитектура, DSL, ADR, тест-план
```

## Быстрый старт (офлайн)
1. Установите Rust toolchain (`rustup`) и выполните vendoring зависимостей:
   ```bash
   make -C pkg vendor
   ```
2. Соберите рабочие бинарники:
   ```bash
   make -C pkg build-linux
   ```
3. При необходимости обновите конфигурацию `config/config.toml` (ключ шифрования, лимиты БД).
4. Для генерации тестового трафика:
   ```bash
   python3 tools/traffic_gen.py --scenario listener --port 8080
   ```

## Запуск программы
После подготовки окружения можно использовать административный CLI. Все команды выполняются из корня репозитория.

### Windows: сборка и запуск `.exe`
Соберите CLI для Windows (исполняемый файл `nets.exe`) и запустите любой режим командной строки PowerShell:
```powershell
cargo build --release --target x86_64-pc-windows-msvc -p cli
./target/x86_64-pc-windows-msvc/release/nets.exe --config .\config\config.toml tui
```
Исполняемый файл можно копировать на офлайн-хост и запускать напрямую (`nets.exe flows --limit 20`). Для создания установщика MSI используйте `make -C pkg package-msi` на хосте Windows с установленным WiX Toolset.

### Режим живого просмотра потоков

### Графический интерфейс (Tauri UI)
1. Перейдите в каталог `app/ui` и установите зависимости (офлайн, если кеш npm уже подготовлен):
   ```bash
   cd app/ui
   npm install --prefer-offline
   ```
2. Для запуска только фронтенда с мок-данными:
   ```bash
   npm run dev
   ```
3. Для запуска полноценного десктопа (Rust + Tauri):
   ```bash
   npm run tauri:dev
   ```
   Интерфейс покажет потоковые таблицы, граф процессов и все вкладки (Flows, Alerts, DNS, Graph, Processes, Settings). Переключение языка происходит моментально без перезагрузки.

```bash
cargo run -p cli -- --config config/config.toml tui
```
Команда поднимает демонстрационный сборщик (mock backend) и выводит поступающие события потоков в консоль. Используется для проверки пайплайна без прав суперпользователя.

### Просмотр последних потоков из локального хранилища
```bash
cargo run -p cli -- --config config/config.toml flows --limit 25
```
Команда открывает шифрованную БД (`nets.db`) и печатает последние N агрегированных потоков.

### Тестирование DSL-правил офлайн
```bash
cargo run -p cli -- --config config/config.toml rule-test --rule-file rules/default.rules
```
Загружает правила, проигрывает демонстрационный поток и выводит сработавшие алерты. Используйте для валидации собственных rule-пакетов перед импортом.

## Документация
* [docs/architecture.md](docs/architecture.md) — диаграммы, угрозмодель.
* [docs/data-schemas.md](docs/data-schemas.md) — JSON Schema и Protobuf контракты.
* [docs/dsl.md](docs/dsl.md) — описание DSL и примеры правил.
* [docs/test-plan.md](docs/test-plan.md) — стратегия тестирования и DoD.
* ADR: [docs/adr/](docs/adr/).

## Тестирование
* Юнит-тесты: `cargo test --workspace`.
* Аномалии: `tests/anomaly_scenarios.sh` (генерация PCAP и listener).
* Перфоманс: `tests/perf_memory.sh`, `tests/perf_cpu.sh` (требуют sudo/perf).

## Пакетирование (офлайн)
* Debian/Ubuntu:
  ```bash
  make -C pkg package-deb
  ```
* RHEL/Fedora:
  ```bash
  make -C pkg package-rpm
  ```
* Windows: `scripts/package-msi.ps1` (требуется WiX).
* macOS: `scripts/package-dmg.sh`.

## Лицензия
Apache-2.0.
