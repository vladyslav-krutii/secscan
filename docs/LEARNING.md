# SecScan: що зроблено і чому

Цей файл — конспект для навчання й підготовки до співбесіди. Після кожного
коміту сюди додається запис: що зроблено, кілька питань «як на співбесіді»
і посилання на офіційну документацію.

---

## Фаза 0 — базовий проєкт (470662c … 04bc721)

**Що і навіщо.** Зробили FastAPI-сервіс `/scan`, який перевіряє HTTP security
headers сайту й ставить оцінку від A до F. Навколо нього побудували повний
DevOps-конвеєр:
- Dockerfile у два етапи (multi-stage), застосунок працює не від root;
- docker-compose з Prometheus і Grafana;
- маніфести Kubernetes, перевірені в кластері kind;
- CI в GitHub Actions: ruff → pytest → збірка → Trivy → push у GHCR.

**Питання.**
- *Навіщо multi-stage Dockerfile?* — У фінальний образ потрапляють тільки venv
  і код, без компіляторів і кешу pip. Образ виходить меншим, і в ньому менше
  вразливостей.
- *Чому контейнер працює не від root?* — Якщо застосунок зламають, нападник
  отримає права звичайного користувача, а не root усередині контейнера. Це
  ускладнює втечу з контейнера.
- *Навіщо `/metrics`?* — Prometheus періодично забирає метрики (pull-модель),
  а Grafana будує з них графіки. Так видно навантаження й помилки без
  читання логів.

**Документація.**
- https://docs.docker.com/build/building/best-practices/
- https://prometheus.github.io/client_python/
- https://grafana.com/docs/grafana/latest/administration/provisioning/
- https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
- https://kind.sigs.k8s.io/

---

## Фаза 1 — SSRF у `/scan` (453f7dc, f84f1df, 352f4a6)

**Що і навіщо.** Сканер ходив за будь-якою URL, тому через нього можна було
дістатися до внутрішніх адрес: `127.0.0.1`, `169.254.169.254` (метадані
хмари), локальної мережі. Тепер кожен крок запиту, включно з кожним
редиректом, перевіряється так:
- дозволені тільки http/https і порти 80/443;
- DNS-ім'я резолвиться, і IP має бути публічним (allowlist через
  `ipaddress.is_global`);
- з'єднання «прибите» до вже перевіреного IP, тому DNS rebinding не працює.

**Питання.**
- *Що таке SSRF?* — Server-Side Request Forgery: нападник змушує сервер
  зробити запит туди, куди сам нападник дістатися не може (внутрішня мережа,
  cloud metadata).
- *Чому allowlist, а не blocklist?* — Blocklist завжди щось пропустить: IPv6,
  IPv4-mapped адреси, NAT64, десятковий запис IP. Allowlist пропускає тільки
  те, що гарантовано публічне.
- *Що таке DNS rebinding і як ми від нього захищені?* — Ім'я спершу резолвиться
  в публічний IP і проходить перевірку, а при наступному запиті вже вказує на
  внутрішній. Ми підключаємося саме до перевіреного IP, а ім'я передаємо в
  `Host` і SNI.

**Документація.**
- https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- https://docs.python.org/3/library/ipaddress.html
- https://www.python-httpx.org/advanced/transports/

---

## Фаза 2 — захист від зловживань (cd5f592 … 18ea0c5)

**Що і навіщо.** Без обмежень сканер можна використати для DoS або як
«безкоштовний проксі». Додали чотири захисти, у такому порядку:
1. rate limit: 10 запитів за хвилину на IP → відповідь 429;
2. ліміт одночасних сканів → 503;
3. загальний дедлайн на скан → 504;
4. метрики для кожного з цих випадків.

IP клієнта беремо з `X-Forwarded-For` тільки тоді, коли запит прийшов від
довіреного проксі.

**Питання.**
- *Чому не можна просто довіряти `X-Forwarded-For`?* — Клієнт може записати
  туди будь-що й так обійти rate limit. Довіряти цьому заголовку можна тільки
  тоді, коли його поставив наш власний проксі.
- *Яке обмеження має in-memory лімітер?* — Кожна репліка рахує запити окремо,
  тож при N подах ліміт фактично стає N×. Рішення — спільне сховище,
  наприклад Redis.
- *Чим відрізняються 429, 503 і 504?* — 429: цей клієнт робить забагато
  запитів. 503: сервер зараз зайнятий. 504: цільовий сайт не відповів
  вчасно.

**Документація.**
- https://slowapi.readthedocs.io/
- https://limits.readthedocs.io/
- https://docs.python.org/3/library/asyncio-task.html#asyncio.timeout
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For

---

## Фаза 3 — оцінка за значенням заголовків (09e5db3 … 124ce1d)

**Що і навіщо.** Раніше заголовок отримував бали, щойно був присутній.
Наприклад, `HSTS: max-age=0` теж давав бали, хоча фактично вимикає HSTS.
Тепер у `app/rules.py` є чисті функції `значення → (частка балів 0..1,
список проблем)` для всіх шести заголовків. CSP `frame-ancestors` має
пріоритет над X-Frame-Options. У Grafana додали панелі для 429/503/504/SSRF.

**Питання.**
- *Чому правила — це чисті функції?* — Вони не мають побічних ефектів, тож їх
  легко тестувати окремо від мережі, і кожне правило можна перевірити своїм
  unit-тестом.
- *Що поганого в `'unsafe-inline'` у CSP?* — Він дозволяє будь-який inline
  JavaScript, а саме від такого XSS CSP і має захищати. Винятки — nonce або
  hash у тій самій директиві.
- *Чому `frame-ancestors` важливіший за X-Frame-Options?* — Так визначає
  специфікація CSP3, і браузери ігнорують XFO, коли є `frame-ancestors`. До
  того ж він гнучкіший: дозволяє задати список дозволених джерел.

**Документація.**
- https://www.rfc-editor.org/rfc/rfc6797
- https://www.w3.org/TR/CSP3/
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy
- https://owasp.org/www-project-secure-headers/

---

## Фаза 4, slice 1 — supply-chain перевірки в CI

### c29a066 — actions запінені по SHA, мінімальні права

**Що і навіщо.** Тег на кшталт `@v4` можна пересунути на інший код. Саме так
19.03.2026 зламали `aquasecurity/trivy-action`: майже всі теги перенаправили
на код, який крав секрети з CI. Повний SHA коміту змінити неможливо.

Ще дві зміни:
- `permissions: {}` для всього workflow, і кожен job отримує тільки потрібні
  йому права;
- `persist-credentials: false`, щоб токен не лишався в `.git/config`.

Нові мажорні версії actions працюють на Node 24, тож зникли попередження про
Node 20.

**Питання.**
- *Як оновлювати запінені SHA?* — Через Dependabot (`github-actions`
  ecosystem). Він оновлює SHA і коментар `# vX.Y.Z` разом.
- *Що дає `permissions: {}`?* — `GITHUB_TOKEN` без прав. Якщо крок зламають,
  нападник не зможе ні пушити, ні змінювати релізи.
- *Чи безпечно запінити тег Docker-образу?* — Ні, тег Docker теж змінний.
  Пінимо `image:tag@sha256:digest`.

**Документація.**
- https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions
- https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions#permissions
- https://www.aquasec.com/blog/trivy-supply-chain-attack/

### 83b8246 — Gitleaks (секрети) і Semgrep (SAST)

**Що і навіщо.**
- Gitleaks проходить **всю історію git** (`fetch-depth: 0`) і шукає ключі,
  токени та паролі. Секрет, видалений у новому коміті, все одно лишається в
  історії.
- Semgrep — статичний аналіз коду (SAST) за наборами правил для Python,
  Dockerfile і GitHub Actions.

Обидва запускаються як контейнери, запінені по digest. Образ збирається
тільки якщо обидві перевірки пройшли.

**Питання.**
- *Що робити, якщо секрет потрапив у git?* — Спершу **відкликати й замінити**
  секрет, і тільки потім чистити історію. Він уже міг бути скопійований.
- *SAST чи DAST?* — SAST читає код без запуску. DAST атакує застосунок, що
  працює. Вони доповнюють одне одного.
- *Чому `--metrics=off`?* — Щоб Semgrep не надсилав телеметрію назовні з CI.

**Документація.**
- https://github.com/gitleaks/gitleaks
- https://semgrep.dev/docs/cli-reference
- https://semgrep.dev/explore

### 53a1a8d — Trivy 0.76.2 + SARIF у вкладку Security

**Що і навіщо.** Trivy сканує готовий образ: пакети ОС і Python-бібліотеки.
Результати HIGH/CRITICAL йдуть у форматі SARIF у GitHub code scanning, де їх
видно як alerts, з історією та статусами. Гейт, як і раніше, валить збірку
тільки на CRITICAL. Для завантаження потрібне право
`security-events: write`.

**Питання.**
- *Що таке SARIF?* — Стандартний JSON-формат результатів статичного аналізу.
  Його розуміють GitHub, IDE та інші інструменти.
- *Навіщо `--ignore-unfixed`?* — Щоб не блокувати збірку через вразливості,
  для яких ще не існує виправлення. Їх видно, але вони не ламають конвеєр.
- *Чому гейт тільки на CRITICAL?* — Це компроміс між безпекою і швидкістю
  розробки. HIGH видно у вкладці Security, і їх виправляють планово.

**Документація.**
- https://trivy.dev/latest/docs/
- https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github

### eb23d06 — pip-audit (вразливі залежності)

**Що і навіщо.** pip-audit перевіряє Python-залежності за базою вразливостей
PyPI/OSV. Trivy бачить тільки те, що вже лежить в образі. pip-audit
перевіряє ще й dev-залежності (pytest, ruff) і працює до збірки образу.
Першим запуском знайшов 16 вразливостей: у starlette 0.41.3 (приходить
транзитивно через fastapi) і в pytest 8.3.4.

**Розбір job'а по рядках.**

| Рядок | Що робить і навіщо |
|---|---|
| `deps:` | Ідентифікатор job'а; на нього посилається `needs:`. |
| `name: Dependencies (pip-audit)` | Назва, яку видно в інтерфейсі GitHub. |
| `runs-on: ubuntu-latest` | Чиста одноразова VM від GitHub для кожного запуску. |
| `permissions: contents: read` | Токен може тільки читати код. Job нічого не пушить і не пише в Security, тож інші права дали б нападнику зайві можливості, якби крок зламали. |
| `actions/checkout@<sha>` | Завантажує код репозиторію. SHA, а не тег, бо SHA неможливо підмінити. |
| `persist-credentials: false` | Інакше checkout зберігає `GITHUB_TOKEN` у `.git/config`, і будь-яка наступна команда (наприклад, шкідливий пакет під час `pip install`) могла б його прочитати. |
| `actions/setup-python@<sha>`, `python-version: "3.12"` | Та сама версія Python, що в образі, тому залежності резолвляться однаково. |
| `pip install pip-audit==2.10.1` | Точна версія інструмента: збірка відтворювана, і нова версія не підтягнеться сама. |
| `pip-audit ... -r requirements.txt -r requirements-dev.txt` | Перевіряє обидва файли залежностей. |
| `--strict` | Валить збірку також тоді, коли якийсь пакет не вдалося перевірити (а не тихо пропускає його). |
| `--desc` | Додає опис кожної вразливості в лог. |
| `needs: [..., deps]` у `build-scan-push` | Образ не збирається й не пушиться, поки залежності не чисті. |

**Як pip-audit знаходить транзитивні залежності.** З `-r` він створює
тимчасове ізольоване середовище й просить pip **розв'язати повне дерево
залежностей**. У нас `fastapi==0.115.6` вимагає `starlette`, pip обирає
конкретну версію (0.41.3), і pip-audit перевіряє кожен пакет у цьому дереві,
а не тільки рядки з файлу.

**Чому збірка падає.** Якщо знайдено хоч одну відому вразливість, pip-audit
завершується з кодом виходу 1. GitHub Actions вважає будь-який ненульовий код
помилкою кроку, тому job стає червоним, а залежний `build-scan-push`
пропускається.

**Питання.**
- *Що таке транзитивна залежність?* — Залежність нашої залежності. Ми не
  писали `starlette` у requirements, але отримали його через fastapi.
- *Чим pip-audit відрізняється від Trivy?* — pip-audit перевіряє файли
  залежностей до збірки, включно з dev-пакетами. Trivy перевіряє готовий
  образ, включно з пакетами ОС.
- *Коли можна використати `--ignore-vuln`?* — Тільки з причиною (вразливий
  код не викликається, виправлення немає) і з датою, коли переглянути. Інакше
  це просто приховування проблеми.

**Документація.**
- https://github.com/pypa/pip-audit
- https://osv.dev/
- https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions#jobsjob_idneeds
- https://github.com/actions/checkout#usage
