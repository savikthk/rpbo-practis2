# RBPO Demo Guide - Postman + GUI

> **baseUrl:** `http://10.88.216.221:8081` (или `http://localhost:8081` если бек локально)
> **Перед каждым демо:** убедись что ZeroTier подключён и бек запущен.

---

## 1. Регистрация нового пользователя

**Postman: POST** `{{baseUrl}}/api/auth/register`
```json
{
  "username": "student1",
  "password": "Student123!@#",
  "email": "student1@example.com",
  "firstName": "Ivan",
  "lastName": "Petrov"
}
```
**Ответ 200:** пользователь создан. Теперь можно логиниться через GUI.

---

## 2. Логин

### 2a. Через Postman (нужен токен для управления лицензиями)

**Postman: POST** `{{baseUrl}}/api/auth/login`
```json
{
  "username": "admin",
  "password": "Admin123!@#"
}
```
**Ответ:** `{ "accessToken": "eyJ...", "refreshToken": "..." }`
Скрипт автоматически сохранит `accessToken` в переменную коллекции.

### 2b. Через GUI

Кликнуть иконку в трее → ввести логин/пароль → "Войти".

---

## 3. Создание лицензии (только ADMIN в Postman)

> Сначала выполни **Login as ADMIN** чтобы получить токен.

**Postman: POST** `{{baseUrl}}/api/licenses`
**Header:** `Authorization: Bearer {{accessToken}}`
```json
{
  "productId": 1,
  "typeId": 1,
  "ownerId": 2,
  "deviceCount": 2,
  "description": "License for student demo"
}
```
- **ownerId** — id пользователя (admin=1, зарегистрированный user=2, 3...)
- **deviceCount** — сколько устройств может активировать

**Ответ:**
```json
{
  "id": 5,
  "code": "XXXX-XXXX-XXXX-XXXX",
  "productId": 1,
  ...
}
```
**Скопируй `code`** — это ключ активации для GUI.

---

## 4. Активация лицензии

### 4a. Через GUI (основной способ)

1. Залогинься в GUI
2. На экране "Активация" вставь ключ `XXXX-XXXX-XXXX-XXXX`
3. Нажми "Активировать"
4. Если OK — откроется экран сканирования

### 4b. Через Postman (для тестирования)

**POST** `{{baseUrl}}/api/licenses/activate`
**Header:** `Authorization: Bearer {{accessToken}}`
```json
{
  "activationKey": "XXXX-XXXX-XXXX-XXXX",
  "deviceMac": "AA:BB:CC:DD:EE:01",
  "deviceName": "TestPC"
}
```
**Ответ:** SignedTicketResponse с `ticket.expiryDate` и `signature`.

---

## 5. Проверка лицензии (Check)

**POST** `{{baseUrl}}/api/licenses/check`
**Header:** `Authorization: Bearer {{accessToken}}`
```json
{
  "deviceMac": "18:C0:4D:53:A7:C7",
  "productId": 1
}
```
- **deviceMac** — MAC текущего ПК (служба определяет автоматически)
- Если лицензия активна → **200** с тикетом
- Если не активирована → **404**
- Если заблокирована → **403**

> GUI проверяет лицензию автоматически каждые 5 секунд.

---

## 6. Сценарий: Блокировка лицензии админом

Этот сценарий показывает что если админ заблокирует лицензию на бэкенде,
GUI через 5 секунд покажет "Лицензия заблокирована".

1. Активируй лицензию в GUI (шаг 4a)
2. Убедись что открылся экран сканирования
3. В **Postman** (или в админке бэка) заблокируй лицензию
   - Если есть эндпоинт блокировки — используй его
   - Или удали запись активации из БД
4. Через 5 секунд GUI покажет: **"Лицензия заблокирована администратором"**
5. Пользователя выкинет на экран активации

---

## 7. Сценарий: Истечение лицензии

Если при создании лицензии на бэке срок = 1 минута (зависит от настроек бэка),
через минуту GUI покажет: **"Срок лицензии истёк"**.

На практике срок = 30 дней (видно в логе: `exp=2026-06-21...`).

---

## 8. Продление лицензии (Renew)

**POST** `{{baseUrl}}/api/licenses/renew`
**Header:** `Authorization: Bearer {{accessToken}}`
```json
{
  "activationKey": "XXXX-XXXX-XXXX-XXXX"
}
```
Продлевает срок действия. После продления GUI автоматически подхватит новый срок.

---

## 9. Сигнатуры антивируса (ADMIN)

### Получить всю базу
**GET** `{{baseUrl}}/api/signatures`
**Header:** `Authorization: Bearer {{accessToken}}`

### Создать сигнатуру
**POST** `{{baseUrl}}/api/signatures`
```json
{
  "threatName": "EICAR.Test.Virus",
  "firstBytesHex": "5835",
  "remainderHashHex": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "remainderLength": 0,
  "fileType": "exe",
  "offsetStart": 0,
  "offsetEnd": 2
}
```

### Обновить сигнатуру
**PUT** `{{baseUrl}}/api/signatures/{{signatureId}}`
(тело аналогично Create, но с обновлёнными полями)

### Удалить сигнатуру (логическое удаление)
**DELETE** `{{baseUrl}}/api/signatures/{{signatureId}}`
Ответ: **204 No Content**

### История версий
**GET** `{{baseUrl}}/api/signatures/{{signatureId}}/history`

### Аудит
**GET** `{{baseUrl}}/api/signatures/{{signatureId}}/audit`

### Бинарная выгрузка (Task 5)
**GET** `{{baseUrl}}/api/binary/signatures/full`
**Header:** `Accept: multipart/mixed,*/*`
Ответ: бинарные файлы `manifest.bin` + `data.bin`

---

## 10. Полный демо-сценарий для препода (5 мин)

| # | Действие | Где | Ожидаемый результат |
|---|----------|-----|---------------------|
| 1 | Запустить службу | PowerShell (admin): `install_service.ps1` | Иконка в трее |
| 2 | Кликнуть иконку | Трей | Окно открывается |
| 3 | Залогиниться | GUI: admin / Admin123!@# | Экран активации |
| 4 | Создать лицензию | Postman: Create License | Получить code |
| 5 | Активировать | GUI: вставить code | Экран сканирования |
| 6 | AV Ping | GUI: кнопка AV Ping | "AV module ready" |
| 7 | Скан файла | GUI: Файл... → выбрать | "Угрозы не обнаружены" |
| 8 | Скан папки | GUI: Папка... → выбрать | "No threats detected" |
| 9 | Расписание | GUI: путь + Установить | "Расписание установлено" |
| 10 | Закрыть окно | Нажать × | Скрыто в трей |
| 11 | Открыть из трея | Клик по иконке | Окно снова видно |
| 12 | Выйти из аккаунта | GUI: кнопка | Возврат на логин |
| 13 | Файл → Выход | Меню | Служба + GUI завершены |

---

## Учётные записи

| Роль | Логин | Пароль |
|------|-------|--------|
| Админ | admin | Admin123!@# |
| Тестовый юзер | testuser | Test123!@# |
| Новый юзер | (создать через Register) | (свой пароль) |

---

## Частые проблемы

| Проблема | Решение |
|----------|---------|
| "Network error" при логине | Проверь ZeroTier + бэкенд: `Test-NetConnection 10.88.216.221 -Port 8081` |
| "Лицензия заблокирована" сразу после активации | Создай НОВЫЙ ключ в Postman, старый мог быть использован |
| Иконка не появилась | Подожди 5 сек или проверь что служба запущена: `Get-Service RBPOService` |
| GUI не открывается | Проверь лог: `Get-Content build\Release\rbpo-service.log -Tail 20` |
