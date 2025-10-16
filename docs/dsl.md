# NETS Flow DSL

## Цели
* Человекочитаемые правила корреляции потоков.
* Работает офлайн, без внешних зависимостей.
* Умеет ссылаться на свойства процесса, сети и метрик частоты.

## Синтаксис (EBNF)
```
rule         = "rule" rule_id "{" rule_body "}" ;
rule_body    = (statement)* ;
statement    = condition_line | meta_line ;
meta_line    = "summary" ":" string
             | "severity" ":" severity
             | "rationale" ":" string
             | "suggest" ":" string ;
condition_line = "when" boolean_expr "->" action ;
boolean_expr = disjunction ;
disjunction  = conjunction { "or" conjunction } ;
conjunction  = predicate { "and" predicate } ;
predicate    = comparison | function_call | "(" boolean_expr ")" | "not" predicate ;
comparison   = field comparator literal ;
field        = identifier { "." identifier } ;
comparator   = "==" | "!=" | "in" | "matches" ;
literal      = string | number | list ;
list         = "[" [ literal { "," literal } ] "]" ;
function_call = identifier "(" [ arguments ] ")" ;
arguments    = literal { "," literal } ;
action       = "alert" "(" string "," severity ")"
             | "quarantine" "(" duration ")" ;
severity     = "low" | "medium" | "high" ;
duration     = number ("s" | "m" | "h") ;
identifier   = ? ASCII_ALPHA ? { ? ASCII_ALPHANUMERIC or '_' ? } ;
string       = '"' { ? any char except '"' ? } '"' ;
number       = ? digits ? ;
```

## Предопределённые функции
* `lan(ip)`: возвращает `true`, если IP относится к RFC1918/fe80::/10.
* `listener(port)`: проверяет, что поток представляет локальный listener (state==LISTEN и direction==Inbound).
* `rate(field, window, threshold)`: вычисляет среднюю частоту события `field` за окно `window` (например, `"dns.nxdomain"`) и сравнивает с порогом.
* `burst(count, window)`: количество событий за окно.

## Поля
* `proc.name`, `proc.sha256`, `proc.user`
* `dst.port`, `src.port`, `dst.ip`, `src.ip`
* `proto`, `state`, `dns.qname`, `dns.rcode`
* `bytes`, `packets`

## Примеры правил
```yaml
- id: listener-unexpected
  severity: High
  summary: "Неожиданный локальный веб-сервер"
  rationale: "Новый listener вне списка разрешённых"
  suggested_action: "Проверить процесс, при необходимости изолировать"
  expression: "listener(8080) and not proc.name in [\"apache2\", \"nginx\"]"
- id: arp-collision
  severity: High
  summary: "ARP коллизия"
  rationale: "Обнаружены разные MAC для одного IP шлюза"
  expression: "function arp_collision"
- id: dns-nx-spike
  severity: Medium
  rationale: "Всплеск NXDOMAIN"
  summary: "Частые NXDOMAIN ответы"
  expression: "rate(\"dns.nxdomain\", \"5m\", 50)"
- id: smb-lateral
  severity: High
  summary: "Латеральные SMB обращения"
  rationale: "Необычный процесс обращается к SMB"
  expression: "proc.name == \"notesync.exe\" and dst.port in [445,139] and lan(dst.ip)"
- id: rdp-burst
  severity: Medium
  summary: "Всплеск RDP"
  expression: "burst(\"rdp\", \"1m\") > 5"
- id: mdns-noise
  severity: Low
  summary: "Повышенный mDNS шум"
  expression: "rate(\"mdns\", \"1m\", 200)"
- id: ssdp-wide
  severity: Medium
  summary: "SSDP широковещательный шторм"
  expression: "rate(\"ssdp\", \"5m\", 300)"
- id: ja3-suspicious
  severity: Medium
  summary: "Неизвестный JA3"
  expression: "ja3 matches \"^badfingerprint\""
- id: unsigned-listener
  severity: High
  summary: "Listener без подписи"
  expression: "listener(0) and proc.signed == false"
- id: high-bytes-out
  severity: Medium
  summary: "Поток с аномально большим outbound объёмом"
  expression: "direction == Outbound and bytes > 104857600"
```

## Семантика действий
* `alert(message, severity)` — создаёт Alert с указанной серьёзностью и текстом.
* `quarantine(duration)` — запрос на карантин процесса/порта на заданное время (всегда требует подтверждения UI).

## Выполнение
1. Normalizer формирует `NormalizedFlow`.
2. Analyzer применяет правила: парсит YAML, строит AST, кэширует функции `rate`/`burst`.
3. При срабатывании `alert` создаётся запись в Storage и прокидывается в UI.
4. `quarantine` публикует `QuarantineDecision` в Policy backend.

## Расширяемость
* Пользователь может импортировать файл `.rules` (YAML) офлайн.
* Валидация: схема + тестовый прогон (CLI `nets-cli rule-test`).
