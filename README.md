# РБПО — Windows-клиент (трей и служба)

Учебный репозиторий с **ветками по заданиям**: от базового трей-приложения до связки со службой, локальным RPC (ALPC), HTTPS к REST API, антивирусным движком и MSI-инсталлятором.

Это **клиентская** часть стека. Сервер REST/JWT и лицензий — Java‑проект **`rbpo_backend`** (Spring Boot).

```text
~/Documents/rbpo_prac      ← этот репозиторий (служба + GUI)
~/Documents/rbpo_backend   ← бэкенд API
```

---

## Ветки и содержание

| Ветка | Что внутри |
| ----- | ----------- |
| **main** | Актуальный код после слияния zad-1 … zad-6. |
| **zad-1** | `rbpo-app.exe`: трей, иконка, меню, single-instance, CMake, GitHub Actions. |
| **zad-2** | `rbpo-app.exe` + `rbpo-service.exe`: запуск GUI в пользовательских сессиях, RPC остановки по `ncalrpc` (ALPC). |
| **zad-3** | Добавлены RPC для auth/license, JWT в памяти службы, HTTPS к `rbpo_backend`, GUI входа и активации продукта. |
| **zad-4** | Антивирусный движок, сканирование файлов / директорий, все необязательные требования (см. ниже). |
| **zad-5** | Хранение AV-баз на диске, проверка ЭЦП манифеста и записей, резервное копирование, обновление по расписанию (см. ниже). |
| **zad-6** | MSI-инсталлятор: установка exe и VC++ зависимостей, регистрация/удаление Windows-службы, сборка на CI. |

---

## Ключевые файлы

| Файл | Назначение |
| ---- | ---------- |
| `src/service/service_main.cpp` | Точка входа службы, все RPC-реализации |
| `src/service/state.cpp` | Auth/license workers, JWT-обновление |
| `src/service/av_engine.h/cpp` | Антивирусный движок (zad-4) |
| `src/service/av_db_io.h/cpp` | Бинарный формат AV-баз на диске (zad-5) |
| `src/rpc/rbpo_rpc.idl` | IDL-интерфейс (MIDL → `rpc_gen/`) |
| `src/main.cpp` | GUI (трей-приложение) |
| `src/rbpo_rpc_constants.h` | Имена службы, endpoint, коды ошибок |
| `installer/Product.wxs` | Описание MSI-пакета (WiX) — файлы, служба, VC++ CRT (zad-6) |
| `.github/workflows/build.yml` | CI-сборка exe и MSI-инсталлятора (zad-6) |

Имя службы: **`RBPOService`**. RPC transport: `ncalrpc`, endpoint `RBPOServiceEndpoint`.

---

## Антивирусный движок (zad-4)

### Структура AV-базы в оперативной памяти

```text
std::map<uint64_t, vector<AvRecord>>
  ключ   — ObjectSignaturePrefix (первые 8 байт сигнатуры, little-endian uint64)
  значение — массив записей AvRecord:
    prefix        (8 байт)  — первые 8 байт сигнатуры
    sigLen        (4 байта) — полная длина сигнатуры
    sigHash              — SHA-256 всех байт сигнатуры (BCrypt)
    offsetBegin   (8 байт) — начало допустимого диапазона позиции (-1 = любая)
    offsetEnd     (8 байт) — конец допустимого диапазона позиции (-1 = любая)
    type          (1 байт) — ObjectType: PE=0, Script=1
    recordSig            — SHA-256 всех вышеперечисленных полей (ЭЦП)
```

`std::map` реализован как красно-чёрное дерево → поиск по префиксу O(log K).

### Алгоритм сканирования (обязательный, п.3)

1. Позиция чтения = 0.
2. Считать 8 байт → поиск по ключу в `std::map` (O(log K)).
3. Для каждой найденной записи (от дешёвой проверки к дорогой):
   - 3.3.1 Тип объекта совпадает с `ObjectType`?
   - 3.3.2 Позиция попадает в `[OffsetBegin, OffsetEnd]`?
   - 3.3.3 Считать ещё `sigLen − 8` байт.
   - 3.3.4 Вычислить SHA-256(prefix_bytes || extra_bytes).
   - 3.3.5 Сравнить хэш с `ObjectSignature`.
4. Несовпавшие записи исключаются; если список пуст — сдвиг на 1 байт, goto 2.
5. Если осталась хоть одна запись — объект вредоносен.

### Алгоритм Ахо-Корасика (необязательный, доп. баллы)

При загрузке базы (`AvLoad`) дополнительно строится автомат из реальных байтов всех сигнатур. `ScanStream` использует AC для одного прохода по файлу O(N + M) вместо O(N log K), проверяя type и offset при совпадении.

### Определение типа файла

| Условие | Тип |
| ------- | --- |
| Расширение `.py`, `.ps1`, `.js`, `.vbs` | Script |
| Первые байты `MZ` | PE |
| Иначе | Script |

### Тестовые сигнатуры

| Сигнатура (16 байт) | Тип | Детект |
| ------------------- | --- | ------ |
| `RBPOTESTVRS1.000` | PE | Файл содержит эту последовательность + MZ-заголовок |
| `#RBPOTESTVRS2.00` | Script | Файл содержит эту последовательность + расширение .py/.ps1 |

### RPC-методы (зарегистрированы в `RBPOServiceRpc`)

**Обязательные:**

| Метод | Описание |
| ----- | -------- |
| `RBPO_GetAvDbInfo` | Дата выпуска базы + кол-во записей |
| `RBPO_ScanFile` | Сканирование одного файла |
| `RBPO_ScanDirectory` | Рекурсивное сканирование директории |

**Необязательные:**

| Метод | Описание |
| ----- | -------- |
| `RBPO_ScanAllDrives` | Сканирование всех несъёмных дисков (`DRIVE_FIXED`) |
| `RBPO_SetScanSchedule` | Установить расписание (путь + интервал в секундах) |
| `RBPO_ClearScanSchedule` | Сбросить расписание |
| `RBPO_GetScheduleResults` | Результаты последнего планового сканирования + timestamp |
| `RBPO_AddMonitorDirectory` | Начать мониторинг директории (`ReadDirectoryChangesW`) |
| `RBPO_RemoveMonitorDirectory` | Остановить мониторинг |
| `RBPO_GetMonitorResults` | Результаты мониторинга (файлы, обнаруженные при создании/изменении) |

Сканирующие методы защищены `LicenseGate()` — требуют активной лицензии.

### GUI (лицензионная панель)

- Метка с датой базы и количеством записей.
- Кнопки: «Скан файл», «Скан папку», «Скан все диски».
- Секция расписания: поле пути, поле интервала (сек), «Установить» / «Сбросить» / «Результаты».
- Секция мониторинга: поле пути, «Добавить» / «Удалить» / «Результаты».

---

## Хранение и обновление AV-баз (zad-5)

### Бинарный формат на диске

Два файла хранятся рядом с `rbpo-service.exe`:

| Файл | Назначение |
| ---- | ---------- |
| `avdb.bin` | Основная база (RBDB v1) |
| `avdb.manifest` | Манифест с HMAC-SHA256 и хэшем файла |
| `avdb.bin.bak` / `avdb.manifest.bak` | Резервная копия (создаётся перед обновлением) |
| `avdb.default.bin` / `avdb.default.manifest` | База по умолчанию (генерируется при первом запуске) |

**Формат `avdb.bin` (RBDB v1):**

```text
[4]  magic 'R','B','D','B'
[2]  version LE uint16 = 1
[4]  record count LE uint32
[2]  date UTF-8 length LE uint16
[N]  date UTF-8
[32] DataHash = SHA-256 всей секции записей
---- секция записей ----
для каждой записи:
  [8]  prefix LE uint64
  [4]  sigLen LE uint32
  [1]  sigHash length (0 или 32)
  [N]  sigHash bytes
  [8]  offsetBegin LE int64
  [8]  offsetEnd   LE int64
  [1]  type (0=PE, 1=Script)
  [1]  hasRemainderHash
  [4]  sigBytes length LE uint32
  [N]  sigBytes
  [2]  threatName UTF-8 length LE uint16
  [N]  threatName UTF-8
  [32] RecordSig = SHA-256(prefix||sigLen||sigHash||offsetBegin||offsetEnd||type)
```

**Формат `avdb.manifest` (RBMF v1):**

```text
[4]  magic 'R','B','M','F'
[2]  version LE uint16 = 1
[32] FileHash = SHA-256 содержимого avdb.bin
[32] ManifestSig = HMAC-SHA256(key, magic||version||FileHash)
```

### Логика загрузки при запуске

```text
1. Сгенерировать avdb.default.bin если отсутствует.
2. Проверить HMAC-манифест avdb.manifest:
   а. Успех → загрузить avdb.bin, проверить ЭЦП каждой записи,
              невалидные пропустить.
              Если пропущены записи + сеть доступна → принудительное обновление.
   б. Неуспех + сеть + токен → принудительное обновление с backend.
3. Если база не загружена → проверить avdb.manifest.bak → загрузить avdb.bin.bak.
4. Если резервная копия недоступна → загрузить avdb.default.bin.
```

### Периодическое обновление

- Фоновый поток стартует при запуске службы (`AvDbStartUpdate(3600)`).
- Каждые 3600 с (при наличии access token):
  1. Сохранить текущую базу в `avdb.bin.bak` / `avdb.manifest.bak`.
  2. Загрузить свежие записи с `GET /api/signatures`.
  3. Записать `avdb.bin` + `avdb.manifest`.
  4. При ошибке записи — откатить базу из резервной копии.

---

## Связь с бэкендом

Порт по умолчанию **8081** (HTTP). Переопределение: env-переменные `RBPO_BACKEND_HOST`, `RBPO_BACKEND_PORT`, `RBPO_BACKEND_USE_TLS`.

| Endpoint | Назначение |
| -------- | ---------- |
| `POST /api/auth/login` | Логин (тело: `username` / `password`) |
| `POST /api/auth/refresh` | Обновление JWT |
| `GET /api/auth/me` | Профиль пользователя |
| `POST /api/licenses/activate` | Активация ключа |
| `POST /api/licenses/check` | Проверка лицензии |

---

## Сборка (Windows)

```bat
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Артефакты: `build/Release/rbpo-app.exe`, `build/Release/rbpo-service.exe`. Оба exe должны лежать в **одном каталоге**.

### Установка службы

```bat
sc create RBPOService binPath= "C:\path\to\rbpo-service.exe" start= demand DisplayName= "RBPO Service"
sc start RBPOService
```

### Удаление службы

```bat
sc stop RBPOService
sc delete RBPOService
```

### Установка через MSI

Собранный инсталлятор `RBPO-Setup.msi` (ветка `zad-6`) выполняет установку «из коробки»:

- Копирует `rbpo-app.exe` и `rbpo-service.exe` в `C:\Program Files\RBPO`.
- Устанавливает VC++ 2022 CRT через Merge Module (автоматический учёт ссылок Windows Installer).
- Регистрирует и запускает службу `RBPOService` с типом запуска **Automatic**.

При удалении через «Установку и удаление программ»:

- Останавливает и удаляет службу `RBPOService`.
- Удаляет все файлы приложения.
- Удаляет VC++ CRT, если он не используется другими продуктами (reference counting MSM).

Локальная сборка MSI (требуется WiX Toolset v3.11):

```powershell
.\installer\build.ps1 -SourceDir "build\Release" `
    -VCRedistPath "C:\Program Files (x86)\Common Files\Merge Modules\Microsoft_VC143_CRT_x64.msm"
```

---

## CI

Workflow `.github/workflows/build.yml` собирает оба exe на `windows-latest`, а для `x64` дополнительно собирает `RBPO-Setup.msi` и публикует его в артефакты.
