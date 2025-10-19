# Развертывание на Windows

## Требования

### Системные требования
- Windows 10 версия 1809 (October 2018 Update) или новее
- Windows 11 (любая версия)
- x64 архитектура
- Минимум 4 ГБ RAM
- 500 МБ свободного места на диске

### Зависимости
- .NET 6.0 или выше (для сборки)
- Visual Studio 2019/2022 Build Tools (опционально)
- Rust 1.70+ и Cargo

## Сборка из исходников

### 1. Установка окружения

```powershell
# Установить Rust
winget install --id Rustlang.Rustup

# Добавить Windows target
rustup target add x86_64-pc-windows-msvc

# Установить Node.js (для UI)
winget install --id OpenJS.NodeJS

# Установить Tauri CLI
cargo install tauri-cli
```

### 2. Клонирование репозитория

```powershell
git clone https://github.com/yourusername/nets.git
cd nets
```

### 3. Сборка приложения

```powershell
# Установить зависимости UI
cd app/ui
npm install

# Собрать полное приложение
cargo tauri build

# Результат в: app/ui/src-tauri/target/release/bundle/msi/
```

### 4. Создание MSI пакета

```powershell
# Использовать WiX Toolset для создания установщика
cd scripts
.\package-msi.ps1
```

## Установка

### Через MSI пакет (рекомендуется)

1. Скачайте `NETS-1.0.0-x64.msi`
2. Запустите установщик от имени администратора
3. Следуйте инструкциям мастера установки
4. Приложение будет установлено в `C:\Program Files\NETS`

### Через Portable версию

1. Скачайте `NETS-portable-x64.zip`
2. Распакуйте в желаемую директорию
3. Запустите `NETS.exe` от имени администратора

## Конфигурация

### Файлы конфигурации

Конфигурация хранится в:
```
%APPDATA%\NETS\config.toml
```

### Базовая конфигурация

```toml
[collector]
# Интервал сбора данных (секунды)
poll_interval = 2

# Максимальное количество потоков в памяти
max_flows = 2000

[analyzer]
# Включить детекцию аномалий
enable_anomaly_detection = true

# Уровень чувствительности (low, medium, high)
sensitivity = "medium"

[storage]
# Путь к базе данных
db_path = "%APPDATA%\\NETS\\flows.db"

# Шифрование базы данных
encrypt = true

# Срок хранения данных (дни)
retention_days = 30

[network]
# Мониторить только локальную сеть
lan_only = false

# Игнорировать loopback трафик
ignore_loopback = true

[ui]
# Язык интерфейса (en, ru)
language = "en"

# Тема (light, dark, auto)
theme = "auto"

# Частота обновления UI (миллисекунды)
refresh_interval = 1000
```

## Права доступа

### Необходимые привилегии

Для полной функциональности требуются права администратора:
- Чтение расширенных TCP/UDP таблиц
- Доступ к информации о процессах
- Создание правил Windows Firewall
- Завершение процессов

### Запуск без администратора

При запуске без прав администратора:
- ✅ Просмотр собственных процессов
- ✅ Мониторинг сетевых соединений (ограниченно)
- ❌ Блокировка соединений
- ❌ Завершение чужих процессов
- ❌ Доступ к системным процессам

### UAC Bypass (не рекомендуется)

Для автоматического повышения прав:
```xml
<!-- app.manifest -->
<requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
```

## Windows Firewall

### Разрешение в Firewall

При первом запуске Windows может запросить разрешение:
1. Разрешите доступ к частным сетям
2. Опционально: разрешите доступ к публичным сетям

### Ручная настройка

```powershell
# Добавить исключение
New-NetFirewallRule -DisplayName "NETS Monitor" `
    -Direction Inbound `
    -Program "C:\Program Files\NETS\NETS.exe" `
    -Action Allow `
    -Profile Private,Domain

# Проверить правила
Get-NetFirewallRule -DisplayName "NETS Monitor"
```

## Windows Defender

### Исключения

Добавьте исключения для лучшей производительности:

```powershell
# Исключить директорию приложения
Add-MpPreference -ExclusionPath "C:\Program Files\NETS"

# Исключить процесс
Add-MpPreference -ExclusionProcess "NETS.exe"

# Исключить базу данных
Add-MpPreference -ExclusionPath "$env:APPDATA\NETS"
```

## Автозапуск

### Через Task Scheduler (рекомендуется)

```powershell
# Создать задачу
$action = New-ScheduledTaskAction -Execute "C:\Program Files\NETS\NETS.exe"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries

Register-ScheduledTask -TaskName "NETS Monitor" `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings
```

### Через Registry (альтернатива)

```powershell
# Добавить в автозагрузку
$path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $path -Name "NETS" -Value "C:\Program Files\NETS\NETS.exe"
```

## Служба Windows

### Установка как службы

```powershell
# Создать службу
New-Service -Name "NETS" `
    -BinaryPathName "C:\Program Files\NETS\NETS.exe --service" `
    -DisplayName "NETS Network Monitor" `
    -Description "Local network flow monitoring and analysis" `
    -StartupType Automatic

# Запустить службу
Start-Service -Name "NETS"

# Проверить статус
Get-Service -Name "NETS"
```

### Управление службой

```powershell
# Остановить
Stop-Service -Name "NETS"

# Перезапустить
Restart-Service -Name "NETS"

# Удалить
Remove-Service -Name "NETS"
```

## Логирование

### Файлы логов

Логи сохраняются в:
```
%APPDATA%\NETS\logs\
├── nets.log           # Основной лог
├── collector.log      # Лог коллектора
├── analyzer.log       # Лог анализатора
└── errors.log         # Лог ошибок
```

### Уровни логирования

Настройка через переменную окружения:
```powershell
# Детальное логирование
$env:RUST_LOG="debug"
.\NETS.exe

# Только ошибки
$env:RUST_LOG="error"
.\NETS.exe
```

### Windows Event Log

```powershell
# Просмотр событий
Get-EventLog -LogName Application -Source "NETS" -Newest 50

# Экспорт в файл
Get-EventLog -LogName Application -Source "NETS" | 
    Export-Csv -Path "nets-events.csv"
```

## Обновление

### Автоматическое обновление

Приложение проверяет обновления при запуске:
1. Проверка новой версии на GitHub Releases
2. Скачивание MSI пакета
3. Запуск установщика

### Ручное обновление

```powershell
# Скачать новую версию
Invoke-WebRequest -Uri "https://github.com/.../NETS-latest.msi" `
    -OutFile "NETS-update.msi"

# Остановить службу
Stop-Service -Name "NETS"

# Установить обновление
Start-Process msiexec.exe -ArgumentList "/i NETS-update.msi /quiet /norestart" -Wait

# Запустить службу
Start-Service -Name "NETS"
```

## Удаление

### Через панель управления

1. Открыть "Программы и компоненты"
2. Найти "NETS Network Monitor"
3. Нажать "Удалить"

### Через PowerShell

```powershell
# Остановить службу
Stop-Service -Name "NETS" -ErrorAction SilentlyContinue

# Удалить службу
Remove-Service -Name "NETS" -ErrorAction SilentlyContinue

# Удалить через MSI
$app = Get-WmiObject -Class Win32_Product | 
    Where-Object { $_.Name -like "NETS*" }
$app.Uninstall()

# Удалить конфигурацию
Remove-Item -Path "$env:APPDATA\NETS" -Recurse -Force

# Удалить правила Firewall
Remove-NetFirewallRule -DisplayName "NETS*"
```

## Производительность

### Оптимизация

```toml
[collector]
# Увеличить интервал сбора для снижения нагрузки
poll_interval = 5

# Ограничить количество процессов
max_processes = 100

[analyzer]
# Отключить сложные проверки
enable_ja3_fingerprinting = false

[storage]
# Уменьшить срок хранения
retention_days = 7
```

### Мониторинг ресурсов

```powershell
# Проверить использование CPU и памяти
Get-Process -Name "NETS" | 
    Select-Object Name, CPU, WorkingSet, VirtualMemorySize
```

## Troubleshooting

### Приложение не запускается

```powershell
# Проверить зависимости
dumpbin /dependents "C:\Program Files\NETS\NETS.exe"

# Проверить логи
Get-Content "$env:APPDATA\NETS\logs\errors.log" -Tail 50

# Запустить в режиме отладки
.\NETS.exe --debug
```

### Не работает блокировка соединений

```powershell
# Проверить Windows Firewall Service
Get-Service -Name mpssvc
Start-Service mpssvc

# Проверить права
whoami /priv | findstr SeDebugPrivilege
```

### Высокое потребление ресурсов

```powershell
# Собрать trace
.\NETS.exe --trace > trace.log

# Проверить конфигурацию
Get-Content "$env:APPDATA\NETS\config.toml"
```

## Поддержка

- GitHub Issues: https://github.com/yourusername/nets/issues
- Documentation: https://nets.readthedocs.io
- Email: support@example.com
