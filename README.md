# BURHAN | بُرهان

```text
  +------------------------------------------------------+
  |   ____  _   _ ____  _   _    _    _   _               |
  |  | __ )| | | |  _ \| | | |  / \  | \ | |              |
  |  |  _ \| | | | |_) | |_| | / _ \ |  \| |              |
  |  | |_) | |_| |  _ <|  _  |/ ___ \| |\  |              |
  |  |____/ \___/|_| \_\_| |_/_/   \_\_| \_|              |
  |          EVIDENCE FIRST. CLAIMS SECOND.              |
  +------------------------------------------------------+
```

**v0.3.1 — إصلاح تجهيز WSL، وفحص نظام الملفات، وتشغيل يتوقف عند أخطاء التثبيت.**

Python 3.11+ / Linux / standard library only. No pip dependencies, login sessions, AI subscription or required API keys.

> هذا إصدار أولي عملي ومختبَر بالحدود أدناه، **وليس منصة اختبار اختراق شاملة، ولا ضمانًا لاكتشاف ثغرة أو صفر إيجابيات كاذبة.** لم تثبت بعد أفضليته على MOHAMMED في اكتشاف ثغرات لدى أهداف حقيقية.

## إصلاح خطأ WSL: فشل clone ثم No such file

إذا ظهر `chmod ... .git/config.lock failed: Operation not permitted` وأنت داخل `/mnt/c/...`، فقد فشل التنزيل قبل تشغيل الأداة. رسائل `setup.sh: No such file` و`./burhan: No such file` التالية ليست أخطاء مستقلة في الفحص. الحل الموصى به هو التنزيل داخل نظام ملفات Linux، مثل `/home/kali`، وليس تغيير صلاحيات Windows قسرًا أو تشغيل `sudo git clone`.

الإصدار 0.3.1 يضيف `./burhan preflight`: يرفض التثبيت تحت مسارات أقراص Windows المعتادة، ويفحص write/chmod/rename/symlink/execute عبر ملفات مؤقتة داخل مجلد التثبيت، ثم يحذفها. لا يغيّر صلاحيات ملفاتك الأصلية ولا إعدادات WSL. `setup.sh` يستدعي الفحص قبل إنشاء venv، ويتوقف عند أول فشل، ويرفض venv غير مكتملة أو رابطًا لمجلد آخر. أمر `--check` ينفذ فحص الملفات المؤقتة لكنه لا ينشئ بيئة دائمة.

هذه الحواجز لا يمكنها إصلاح `git clone` الذي فشل قبل تنزيلها؛ لذلك يجب أيضًا تنفيذ كتلة التنزيل أدناه داخل Bash مع fail-fast. اختُبرت حالات فشل chmod وsymlink وnoexec بالمحاكاة على Linux؛ لا ندعي تشغيلًا فعليًا داخل جهازك أو WSL.

المراجع الرسمية: [Microsoft: مكان ملفات مشاريع WSL](https://learn.microsoft.com/en-us/windows/wsl/filesystems)، و[تفسير صلاحيات ملفات Windows في WSL](https://learn.microsoft.com/en-us/windows/wsl/file-permissions).

## تشغيل برامج حقيقية دون إدخال السكوب يدويًا

**الكود الكامل على [فرع genspark_ai_developer](https://github.com/mohammedaljohaniit1-max/--------2026/tree/genspark_ai_developer)، وليس main.** إذا ظهر README فقط، غيّر الفرع من قائمة GitHub. [طلب الدمج #1](https://github.com/mohammedaljohaniit1-max/--------2026/pull/1) ما زال منفصلًا عن main؛ لا ندمجه تلقائيًا نيابةً عنك.

راجعت المصادر الرسمية في **11 سبتمبر 2026**. الإعدادات في `programs.json`، وأوامر القائمة/التخطيط لا تتصل بالأهداف:

| البرنامج | النطاق المجهز | الأتمتة في السياسة | إعدادنا |
|---|---|---|---|
| [Clario](https://hackerone.com/clario) | جميع أسماء مضيفي الويب العشرين في [جدول النطاق](https://hackerone.com/clario/policy_scopes)، مقسمة تلقائيًا إلى مرحلتين | طلب واحد/ثانية | طلب كل ثانيتين، اتصال واحد |
| [CS Money](https://hackerone.com/cs_money) | `https://cs.money` و`https://3d.cs.money` فقط | 5 طلبات/ثانية و5 اتصالات متزامنة كحد أقصى | طلب كل ثانيتين، اتصال واحد |

**Clario:** الـ27 صفًا في الجدول تشمل 20 مضيف ويب، تطبيق Mackeeper، ثلاثة عناوين خارج النطاق، وثلاثة عناوين جداول ليست أهدافًا. احتفظنا بها في الفهرس، لكن نفحص HTTPS للمضيفين العشرين فقط، وليس التطبيق التنفيذي أو كل وظائف المواقع. عناوين `account.clario.co` و`api-ne.clario.co` و`api.account.opendoor.ltd` غير مسموحة.

**CS Money:** لم أتمكن من استخراج جدول النطاق المنظم كاملًا؛ الأصلان المختاران مذكوران صراحةً في جدول المكافآت. لا أسمي ذلك السكوب الكامل. استبعدنا `blog.cs.money` ومسار `/blog` بسبب قيود WordPress الخاصة بالبرنامج، ولم نضم `support.cs.money` في هذه المجموعة المحافظة. لا نفحص معاملات التداول/الأرصدة أو حسابات المستخدمين.

هذه ملاءمة لتجربة تشغيل منخفضة الضغط، وليست دليلًا على ضعف الأهداف أو وجود ثغرة قابلة للمكافأة. البرنامجان لا يقبلان تقرير ماسح غير متحقق منه، ومعظم ملاحظات headers/cookies ليست مكافآت مستقلة.

### الأوامر المجمعة — أهداف فعلية، بلا placeholders

```bash
bash <<'BASH'
set -Eeuo pipefail
trap 'printf "Stopped at line %s; do not continue after the failed step.\n" "$LINENO" >&2' ERR
umask 077
cd "$HOME"
case "$(pwd -P)" in /mnt/[a-zA-Z]|/mnt/[a-zA-Z]/*) echo 'Use the Linux home, not a Windows drive.' >&2; exit 1;; esac
sudo apt update
sudo apt install -y git python3 python3-venv openssl ca-certificates
STAMP="$(date -u +%Y%m%dT%H%M%SZ)-$$"
# احتفظ بالنسخة السابقة ونتائجها بدل حذفها:
if [[ -e "$HOME/burhan" || -L "$HOME/burhan" ]]; then
  mv -- "$HOME/burhan" "$HOME/burhan.backup.$STAMP"
fi
git clone --single-branch --branch genspark_ai_developer \
  https://github.com/mohammedaljohaniit1-max/--------2026.git "$HOME/burhan"
cd "$HOME/burhan"
bash setup.sh
./burhan --version
./burhan programs list
./burhan programs show clario
./burhan programs show cs-money
./burhan programs plan all
read -r -p 'Confirm current program rules and eligibility; type YES to scan: ' CONFIRM </dev/tty
[[ "$CONFIRM" == YES ]] || { echo 'Installed. No scan started.'; exit 0; }
mkdir -p outputs
RUN="outputs/bounty-$STAMP"
STATUS=0
./burhan programs scan all --acknowledge-current-rules --out "$RUN" || STATUS=$?
if [[ "$STATUS" != 0 && "$STATUS" != 2 ]]; then exit "$STATUS"; fi
printf '\nReports: %s/%s\n' "$PWD" "$RUN"
cat "$RUN/batch.json"
BASH
```

انسخ الأوامر فقط، لا رموز الطرفية `└─$`. كود الفحص 2 يمثل نتيجة جزئية/توقف مراجعة، لذلك تعالجه الكتلة دون إخفاء أخطاء التثبيت. تحفظ كتلة إعادة التنزيل نسخة Linux السابقة باسم `burhan.backup.*`؛ لا تحذف مجلد `outputs` خارج مجلد المشروع. لعرض تقارير WSL من Windows، يمكنك استخدام `explorer.exe "$HOME/burhan/outputs"` من الطرفية.

إذا كانت الأداة منزّلة مسبقًا، نزّل هذه النسخة في مجلد جديد مثل `burhan-v03` بدل استبدال ملفاتك. سجل فرع التطوير أُعيد تنظيمه عبر squash، لذلك قد يرفض `git pull --ff-only` النسخ القديمة. لا تستخدم `git reset --hard` على مجلد يحوي تعديلاتك أو نتائجك.

لبدء البرنامج المرشح الأول وحده: `./burhan programs scan clario --acknowledge-current-rules --out outputs/clario-first`.

التشغيل `all` متسلسل، وليس متوازيًا: مرحلتان لـClario ومرحلة لـCS Money. حد التخطيط الإجمالي **308 محاولات كحد أقصى**؛ العدد الفعلي غالبًا أقل، ولا يدل وحده على جودة التغطية. يقف التشغيل كله عند أول candidate/verified exposure للمراجعة أو عند Ctrl+C، ويسرد المراحل التي لم تعمل في `batch.json`. هذا توقف احترازي، لا إعلان ثغرة مؤكدة. يمكن إكمال الأبحاث بعد مراجعة الدليل والسياسة، لا بإرسال التقرير تلقائيًا.

**صلاحية المراجعة المحلية تنتهي في 18 سبتمبر 2026 الساعة 23:59 UTC.** بعدها يُمنع `programs scan` حتى إعادة مراجعة النطاق والشروط وتحديث الفهرس؛ ليست هذه نهاية برنامج المكافآت. لا يجلب الأمر الشروط لحظيًا، وقد تتغير قبل هذا التاريخ. `--acknowledge-current-rules` تأكيد منك أنك مؤهل وأن النطاق والقواعد ما زالت تسمح بالاختبارات. وجود صفحة عامة وحده لا يمنح دعوة لبرنامج خاص.

لا تحتاج هذه الفحوص تسجيل دخول للهدف، لكن الإبلاغ والمكافآت يخضعان لحساب المنصة والأهلية وشروط البرنامج. لا نشارك الهدف مع OSINT providers ضمن أمر `programs scan`.

استبعدنا Discourse لتعليق المكافآت المعلن، وMintel لوصفه البرنامج بأنه خاص، وبرامج لم نستطع التحقق من جدول نطاقها. أسباب الاستبعاد ومراجعها محفوظة في `programs.json`.

## 1. الفكرة والصدق في النتائج

قيمة الأداة ليست عدد الأدوات التي تُشغّلها، بل دقة ما يمكنك قوله للعميل: ما الذي اختُبر؟ ما الدليل؟ ما الأثر المثبت؟ وما الذي لم يُختبر؟

- حجم الموقع لا يحدد تحمّله. السياسة المكتوبة هي التي تحدد النطاق والمعدل والوقت.
- الفحص دون تسجيل دخول يستبعد الصلاحيات والعديد من حالات business logic.
- قلة النتائج قد تعني ضعف التغطية، وليس نجاح الفلاتر. لذلك يظهر سجل الأخطاء والاستبعادات منفصلًا.
- لا يُستخدم LLM لتصديق ثغرة أو رفضها. التحليل الموجود قواعد قابلة للتفسير، لا «نموذج عبقري» غير قابل للقياس.
- **لا تؤكد النسخة ثغرات تلقائيًا.** حقل `confirmed_vulnerabilities` يظل صفرًا بحكم نموذج التقرير؛ ليس إحصائية دقة 100%.
- `verified_exposure` يعني إثبات حقيقة تقنية ضيقة، وليس إثبات أثر تجاري أو اختراق كامل.
- لا تصف تقريرًا بلا نتائج بأنه «الهدف آمن». راجع التغطية والقيود.

### ما يعمل الآن وما لا يعمل

| يعمل في هذا الإصدار | غير موجود في هذا الإصدار |
|---|---|
| سياسة origins دقيقة واستبعادات وانتهاء تفويض | فحص صلاحيات/جلسات/منطق أعمال |
| بوابة شبكة موحدة وميزانيات وحدود استجابة | استغلال XSS/SQLi/SSRF/RCE أو تجاوز WAF |
| Git HEAD مع تكرار وnegative controls | تنزيل مستودعات أو استخدام أسرار مكتشفة |
| ملاحظات headers/cookies، وتحليل JS محدود | محلل JS AST/data-flow أو متصفح headless |
| استيراد nuclei/httpx/subfinder/URL outputs | تشغيل وإدارة عشرات الأدوات الخارجية |
| OSINT نطاق عبر CT/archives دون طلب الهدف | Getcontact أو دفاتر جهات اتصال أو ربط هويات أفراد |
| تدقيق محلي لبريد/هاتف/اسم في تصدير مأذون | بحث شامل عن الأشخاص أو ملكية حساباتهم |
| تقارير HTML/JSON/Markdown وhash manifest | توقيع رقمي/تشفير/مراجعة بشرية داخل واجهة |
| إعداد محلي واختبارات قابلة للتكرار | checkpoints مستمرة أو ضمان الاستعادة بعد SIGKILL |

## 2. مراجعة المشروع السابق وملف التسليم

تمت قراءة README V12.6 المرفق وملف HANDOVER كاملًا، ومراجعة شجرة المستودع وعينة من المصدر عند:

`b578c21d6b2b0208833b01f72c2daad8256d3922`

المستودع يتضمن أيضًا إضافات V13 و`HONEST_ASSESSMENT.md`. لم تُشغّل اختبارات المستودع السابق ولم تتم مراجعة كل ملف؛ هذه مراجعة محددة، لا تدقيق كامل.

| دليل المراجعة | الدرس المطبق |
|---|---|
| HANDOVER: 6/7 أهداف بلا DNS حي، وصفر ثغرات مؤكدة | عرض فشل الشبكة والتغطية؛ لا تحويل الفشل إلى نتيجة سلبية |
| HANDOVER: نتائج قديمة تلوث تشغيلًا جديدًا | مجلد جديد لكل تشغيل؛ رفض استبدال تقرير سابق |
| HANDOVER: مشاكل أسماء flags وإصدارات الأدوات | لا flags مختلقة؛ وجود binary ليس إثبات توافق؛ imports فقط حاليًا |
| `false_positive.go:214–219`: إعادة التحقق بفئة HTTP | إعادة فحص نفس المؤشر؛ HTTP200 مرة أخرى لا يكفي |
| `false_positive.go:90–98`: كلمات private-data | email/password ليست دليل خصوصية؛ مؤشرات الأسرار candidates فقط |
| `baseline.go:28–45`: TLS غير متحقق منه وتحويلات | TLS مفعّل؛ لا redirect أو اتصال خارج origin المسموح |
| `differential.go:81–85,161–170`: تساوي بنية JSON | البنية ليست الملكية؛ لا تأكيد IDOR دون سياق حسابات وسياسة |
| `zerofp.go:29–41,85–115`: cloudflare/cf-ray ضمن مؤشرات حظر | وجود CDN ليس حظرًا؛ التحدي الصريح منفصل |

ملف HANDOVER يجمع مقدمة V12.6 وأجزاء أقدم تشير إلى commit `d996776`. أرقام «0 false positives» التاريخية فيه ليست قياسًا مستقلًا لدقة كل الإصدارات، ولا يمكن مقارنتها مباشرة بنتائج الإصدار الحالي.

المصدر: [MOHAMMED snapshot](https://github.com/mohammedaljohaniit1-max/mohammed-V4/tree/b578c21d6b2b0208833b01f72c2daad8256d3922). المشروع الجديد مستقل؛ لم يُغيّر Go module القديم أو ينسخ محرك استغلاله.

## 3. التنزيل والتجهيز على Kali

نفّذ كتلة التنزيل والتجهيز مرة واحدة:

```bash
bash <<'BASH'
set -Eeuo pipefail
cd "$HOME"
case "$(pwd -P)" in /mnt/[a-zA-Z]|/mnt/[a-zA-Z]/*) echo 'Use your Linux home.' >&2; exit 1;; esac
sudo apt update
sudo apt install -y git python3 python3-venv openssl ca-certificates
git clone --single-branch --branch genspark_ai_developer \
  https://github.com/mohammedaljohaniit1-max/--------2026.git burhan
cd burhan
bash setup.sh
./burhan doctor
./burhan --help
BASH
```

إذا كان مجلد `burhan` موجودًا، تتوقف هذه الكتلة دون تغيير محتوياته. استخدم كتلة إعادة التنزيل أعلاه لحفظه كنسخة احتياطية أولًا.

بعد دمج PR يمكن استخدام `main`. إذا كان المستودع خاصًا، استخدم تسجيل GitHub المشروع؛ لا تضع token في README أو أمر ظاهر.

### ماذا يفعل setup.sh؟

1. يفحص Python 3.11+ وOpenSSL وgit.
2. ينشئ `.venv` محليًا دون pip أو حزم تنزيل.
3. يشغّل `doctor` ومجموعة الاختبارات كاملة.
4. لا يكتب إعدادات النظام، ولا يطلب root، ولا ينزّل أدوات غير مستخدمة.
5. يمكن إعادة تشغيله؛ لا يستبدل مجلدًا باسم `.venv` ليس virtual environment.

```bash
bash setup.sh --check  # فحص بيئة ونظام ملفات مؤقت، بلا إنشاء venv
./burhan preflight    # فحص نظام ملفات التثبيت دون شبكة
bash verify.sh        # syntax + الاختبارات + CLI smoke tests
```

اختُبر التشغيل والتجهيز المتكرر هنا على Linux/Python 3.13.14، **وليس داخل تثبيت Kali فعلي**. توافق Kali مستهدف اعتمادًا على Python القياسي؛ لا ندّعي اختبار كل توزيع.

`doctor` محلي فقط: وجود `httpx` مثلًا قد يشير إلى أداة أخرى بالاسم نفسه. لا يُختبر توافق الأدوات الخارجية ولا DNS/Internet بهذا الأمر.

## 4. سياسة التكليف قبل أي فحص

```bash
cp policy.example.json engagement.local.json
nano engagement.local.json
```

القالب منتهي الصلاحية عمدًا و`automation_allowed=false`. عدّل حسب تكليفك الفعلي:

```json
{
  "origins": ["https://app.example.com"],
  "authorization_ref": "SIGNED-ENGAGEMENT-REFERENCE",
  "expires_at": "2026-09-30T18:00:00+00:00",
  "automation_allowed": true,
  "excluded_paths": ["/logout", "/billing"],
  "max_requests": 40,
  "max_seconds": 180,
  "interval_seconds": 1.0,
  "timeout_seconds": 8,
  "max_body_bytes": 262144,
  "max_assets": 6
}
```

الأسماء والتاريخ توضيحيان وليسا تفويضًا. أضف كل scheme/host/port مصرح به صراحة. النطاق `https://app.example.com` لا يشمل HTTP ولا subdomains ولا 8443. لا wildcards ولا CIDR. اختر origin النهائي الصحيح؛ التحويلات لا تتبع.

## 5. أوامر الفحص الخارجي

```bash
mkdir -p outputs

# تخطيط بلا شبكة
./burhan plan --policy engagement.local.json

# فحص محدود، لا يحتاج cookies أو حسابات
./burhan scan --policy engagement.local.json \
  --authorized --out outputs/engagement-001

# تحقق من سلامة ملفات التقرير مقارنة بالـmanifest
./burhan verify outputs/engagement-001

# عرض محلي على Kali desktop
xdg-open outputs/engagement-001/report.html
```

لا يوجد flag اسمه genius/advanced يُشغّل حمولة خفية. كل ما يعمل موضح أدناه، وحدود الميزانية ليست مجرد نصائح.

- `0`: اكتمل البرنامج المخطط، لا يعني سلامة الهدف.
- `1`: خطأ إعداد أو ملف.
- `2`: نتيجة جزئية/مقاطعة. التقرير الجزئي يبقى مفيدًا للمراجعة.
- `--out` يجب أن يكون مجلدًا جديدًا وأبوه موجودًا. اختر اسمًا جديدًا عند إعادة الفحص.
- Ctrl+C يحفظ التقرير الجزئي. SIGKILL/انقطاع الكهرباء قد يفقدان ما لم يُكتب؛ لا resume حاليًا.

### قائمة الفحوص الحقيقية

| الفحص | السلوك | ما لا يثبته |
|---|---|---|
| Root `/` | الرد وملاحظات HSTS/nosniff/خصائص cookies | غياب header ليس ثغرة مؤكدة |
| `/.git/HEAD` | صيغة HEAD صارمة؛ عند المطابقة طلبا control عشوائيان + إعادة HEAD | لا يثبت تنزيل المستودع/الأسرار |
| robots/security.txt/sitemap | جمع الرد وحالته فقط | لا تدقيق RFC أو crawl شامل |
| JS المرتبط بالـHTML | scripts ضمن النطاق، بحد max_assets | لا تنفيذ JS، ولا تحليل حزم شامل |
| Secret-shaped material | أنماط محدودة + entropy، قيمة السر لا تحفظ | لا يثبت صلاحية أو حساسية المفتاح |
| Source maps المرتبطة | تحقق بنية JSON v3 مع sources/mappings | كثير من source maps مقصودة وعامة |

Git HEAD لا يؤكد لمجرد كود 200 أو كلمة git: يجب تكرار نفس المحتوى المطابق، واختلاف الرد عن مساري control. يظل `verified_exposure` حقيقة محدودة، وقد يحتاج تمييز أمثلة تعليمية/honeypots يدويًا.

## 6. OSINT مستقل للموقع — دون لمس الموقع

```bash
./burhan osint domain \
  --domain app.example.com \
  --policy engagement.local.json \
  --share-intel \
  --out outputs/domain-intel-001
```

- `--domain` اسم DNS فقط، ويجب أن يطابق hostname في السياسة؛ ليس رابطًا أو IP أو بريدًا.
- لا HTTP ولا DNS lookup للهدف؛ الاتصالات مع المزودين فقط، عبر بوابة الشبكة نفسها.
- يمكن أن تكون `automation_allowed=false` لأن هذا المسار لا يفحص الهدف؛ ما زال يتطلب نطاقًا مرجعيًا وتفويضًا غير منتهٍ وموافقة مشاركة الاسم.
- `--share-intel` يوافق على إفصاح اسم البحث للمزودين. احترم سياسة العميل وشروط الخدمة.
- الافتراضي: crt.sh + Wayback CDX، bounded first page/sample، دون pagination شاملة أو retry خفي.
- الناتج: أسماء/مسارات تاريخية، timestamps ذات معنى موضح، مصدر وفئة المصدر وevent ID، وما يحتاج موافقة نطاق.
- اسم staging ليس دليل ضعف، وتاريخ شهادة ليس تاريخ آخر اتصال، وwildcard ليس مضيفًا حيًا.
- crt.sh وCert Spotter يعتمدان على CT؛ لا نحسبهما مصدرين مستقلين لإثبات ملكية.
- الأسماء المكتشفة **لا تدخل نطاق الفحص تلقائيًا**. راجعها مع مالك الأصول.

Cert Spotter اختياري للتقييم فقط وفق شروط المصدر:

```bash
./burhan osint domain --domain app.example.com \
  --policy engagement.local.json --share-intel \
  --certspotter-evaluation --out outputs/domain-intel-evaluation
```

توثيقه يسمح بعدد محدود من الطلبات دون مصادقة للتقييم/الاستخدام الشخصي، ويطلب حسابًا ومفتاحًا للإنتاج. لا ندّعي أنه مصدر مجاني إنتاجي غير محدود؛ هذه النسخة لا تضيف key authentication له.

### Shodan InternetDB أثناء الفحص المصرّح به

```bash
./burhan scan --policy engagement.local.json --authorized \
  --share-intel --out outputs/engagement-with-intel
```

هذا **فحص فعلي للهدف** مع إثراء اختياري من crt.sh/InternetDB، وليس مسار OSINT-only السابق. InternetDB يستخدم IP عامًا رُصد أثناء فحص الهدف، ويضع CVEs كخيوط غير مؤكدة. لا يفحص المنافذ المذكورة أو يستخدم بيانات اعتماد. قد يكون IP مشتركًا/CDN وقد تكون بيانات المزود قديمة.

## 7. OSINT للبريد/الهاتف/الاسم: تدقيق محلي مأذون

هذا مسار **محدود وواضح** لتحديد مواضع ظهور بياناتك داخل تصدير تملكه أو مأذون لك بمراجعته، وليس بديلًا عن Getcontact ولا بحثًا عميقًا عن أفراد. لا يجمع ملفات شخصية أو وسوم جهات اتصال، ولا يربط حسابات بأشخاص بناءً على تشابه أسماء.

المدخل JSONL، كل سطر به `content` نصي. مثال اصطناعي:

```json
{"content":"Contact me at self@example.com"}
{"content":"Old public text with +1 (202) 555-0123"}
{"content":"Sample Person"}
```

الأمر يقرأ المعرف من ملف بدل وضعه في history/قائمة العمليات:

```bash
umask 077
nano identifier.local.txt
# ضع معرفك وحده في الملف، ثم احفظه

./burhan osint self-audit --kind email \
  --value-file identifier.local.txt --input authorized-export.jsonl \
  --consented --out outputs/email-audit-001
```

للهاتف أو الاسم غيّر نوع المعرف وملفه:

```bash
./burhan osint self-audit --kind phone \
  --value-file my-phone.local.txt --input authorized-export.jsonl \
  --consented --out outputs/phone-audit-001

./burhan osint self-audit --kind name \
  --value-file my-name.local.txt --input authorized-export.jsonl \
  --consented --out outputs/name-audit-001
```

- الهاتف يتطلب +country code صريحًا؛ لا تخمين بلد أو صاحب الرقم.
- email local-part case و+aliases محفوظة؛ لا دمج هويات افتراضي.
- الاسم يتطلب مساواة الحقل كاملًا بعد تسوية المسافات، لا fuzzy matching.
- الناتج أرقام السجلات والأسطر داخل تصديرك، دون حفظ المعرف أو نصوص الأشخاص الأخرى.
- النتيجة تثبت **تطابق النص المحلي** فقط، لا ملكية حساب أو تسريب أو هوية شخص.
- صفر اتصالات شبكة. الحد 5 MiB/10,000 سجل. ظهور صفر يعني «لا تطابق في هذا التصدير»، لا «لا أثر لك على الإنترنت».

## 8. الاستفادة من أدواتك السابقة — import بلا تشغيل

```bash
./burhan import --policy engagement.local.json --format nuclei \
  --input previous-nuclei.jsonl --out nuclei-review.local.json

./burhan import --policy engagement.local.json --format httpx \
  --input previous-httpx.jsonl --out http-review.local.json

./burhan import --policy engagement.local.json --format subfinder \
  --input previous-subfinder.jsonl --out domains-review.local.json

./burhan import --policy engagement.local.json --format urls \
  --input previous-urls.txt --out urls-review.local.json
```

لا تُشغّل nuclei/subfinder/httpx من هذا المسار. الأصل خارج origins الدقيقة يُرفض حتى لو كان subdomain من نفس المؤسسة. المدخل محدود بـ5 MiB/10,000 سطر. حالات القبول تبقى `unverified_import` مهما قال المصدر `verified=true` أو critical. query values وextracted-results وrequest/response blobs لا تُصدر. الناتج JSON مستقل، وليس نتائج مدمجة تلقائيًا في التقرير الحي.

## 9. هندسة الحواجز والأدلة

```text
Written policy + authorization expiry
                |
URL / origin / exclusion gate BEFORE DNS
                |
Shared request count + pacing + total deadline
                |
Bounded OS resolver subprocess -> validated IP -> pinned TCP
                |
Verified TLS / GET only / no redirects / no cookies / no retries
                |
Bounded response + event identifier + retained-byte hash
                |
Specific predicate -> negative controls -> repeat same predicate
                |
observation / candidate / verified_exposure -> human impact review
```

- origin = scheme+host+port. استبعادات path تطبق بعد decoding مع رفض traversal والأشكال الملتبسة.
- target URLs ذات query تُحصر كمراجع، ولا تُطلب؛ لا نقل secrets في query للطلبات الاختبارية.
- جميع IPs الناتجة يجب أن تكون عامة. private/loopback/link-local أو mixed answers تمنع الاتصال كله.
- TCP يتصل بعنوان IP الذي فُحص؛ Host وTLS SNI الأصليان محفوظان. لا DNS ثانٍ ضمن الاتصال.
- `--lab-loopback-only` للمختبر فقط: origins بعناوين loopback حرفية، دون OSINT. لا خيار يسمح بجميع الشبكات الخاصة.
- لا proxy من environment، ولا TLS insecure fallback، ولا cookies/Authorization، ولا brute force أو account creation.
- افتراضيًا محاولة كل ثانية، حد أدنى 0.5 ثانية، تشغيل متسلسل، 40 محاولة/180 ثانية، مهلة طلب 8 ثوانٍ وجسم حتى 256 KiB.
- عداد المحاولات يشمل فشل DNS/الاتصال بعد حجز الميزانية؛ ليس فقط الردود المكتملة.
- socket deadline يحد أيضًا من الردود التي ترسل headers/body ببطء شديد. DNS في subprocess بمهلة محدودة.
- 429/503 يوقف origin دون retry. كذلك خطآن متتاليان من النقل/5xx أو cf-mitigated: challenge.
- وجود cf-ray وحده ليس حظرًا. الرد الجزئي/المقطوع/التحدي الصريح لا يثبت exposure.
- GET قد يسبب أثرًا في تطبيق مصمم خطأ؛ تحديد المعدل لا يضمن انعدام الأثر ولا يحل محل التفويض.

## 10. التقارير والخصوصية

```text
outputs/run-id/
  report.html
  report.json
  report.md
  manifest.json
```

HTML محلي responsive دون scripts/fonts/images خارجية، مع HTML escaping وCSP. تقرير الفحص يحوي بطاقات النتائج والسياسة وledger؛ تقرير OSINT يعرض البيانات المنظمة كاملة. JSON المرجع التفصيلي؛ Markdown ملخص لا تقرير استشاري نهائي جاهز للإرسال بلا مراجعة.

| الحالة | معناها |
|---|---|
| observation | حقيقة محدودة/إعداد قد يكون مقصودًا |
| candidate | مؤشر يحتاج إثباتًا إضافيًا |
| verified_exposure | تكرر مؤشر تقني محدد مع controls؛ لا تأكيد أثر تجاري |
| unverified_import | نتيجة خارجية لم يُتحقق منها |
| observed في coverage | جُمِع رد/سجل، لا يعني passed |
| skipped/inconclusive/not_tested | تغطية ناقصة، لا نتيجة سلبية |

- ملفات التقرير 0600 والمجلد 0700 على Unix؛ **ليست مشفرة**.
- bodies وheaders في الذاكرة أثناء التحليل؛ لا حفظ cookie values أو قيم الأسرار أو sourcesContent.
- الروابط المصدرة تُزال منها userinfo/query values/fragments؛ التنقية ليست DLP شاملًا.
- أسماء المضيفين وIP والمسارات ومرجع التكليف قد تبقى حساسة. راجع وشفّر قبل المشاركة.
- SHA-256 في event يخص البايتات المحتفظ بها، لا يضمن كامل الرد، ولا يغني عن packet capture أو إعادة تحقق بشرية.
- `verify` يطابق ملفات التقرير مع manifest فقط؛ لا يثبت صحة النتائج أو أصالة الناشر، ومن يغير الملفات والmanifest معًا يتجاوز هذا الفحص.
- لا توجد أرقام CVSS تلقائية أو نسبة precision مختلقة.

## 11. الاختبارات والتجربة المحلية

```bash
bash verify.sh
```

**86 اختبارًا محليًا** تغطي: حدود scope/encoding/DNS، TLS، redirects/cookies، timeouts والردود الجزئية، SPA/catch-all/Git repeat، circuits، حفظ المقاطعة، imports، redaction وHTML safety، OSINT provenance، منع طلب الهدف، وconsented local audit.

الاختبارات لا تستهدف مواقع عامة؛ HTTP/TLS على fixtures مؤقتة في loopback. بعض اختبارات fixtures تزيل انتظار المعدل لتسريع suite؛ هناك اختبار مستقل لمباعدة الطلبات الإنتاجية. OpenSSL CLI يُستخدم لتوليد شهادة محلية لاختبار رفض شهادة غير موثوقة.

### تقرير عرض اصطناعي

```bash
mkdir -p outputs
.venv/bin/python -B - <<'PY'
from pathlib import Path
from test_burhan import fixture, policy
from burhan import Assessment, write_report
with fixture('positive') as (site, requests):
    report = Assessment(policy(site), lab=True).run()
    report['policy']['authorization_ref'] = 'SYNTHETIC LOCAL DEMO - NOT A CLIENT FINDING'
    write_report(report, Path('outputs/demo'))
print('Open outputs/demo/report.html')
PY
xdg-open outputs/demo/report.html
```

قد يظهر `partial` في المثال بسبب script خارجي يُستبعد عمدًا. هذا يثبت عرض القيد، لا فشل المختبر. لا تقدّم تقرير العرض على أنه اكتشاف لدى عميل.

`ci.example.yml` قالب غير مفعّل لـGitHub Actions/Python3.11 و3.13. صلاحية GitHub المتاحة أثناء البناء رفضت إنشاء workflows؛ لذلك **لم تُشغّل CI على GitHub**. يستطيع مالك المستودع تفعيل القالب بصلاحياته بعد المراجعة. الاختبارات المحلية هي ما تم التحقق منه هنا.

## 12. خارطة التطوير ببوابات قبول

الجدول يفصل ما سُلّم عن التطوير المقترح؛ لا توجد وحدات وهمية بأسماء ضخمة.

| المرحلة | الناتج | شرط القبول | الحالة |
|---|---|---|---|
| M0 | scope/policy/expiry/budget | عدم اتصال بوجهة مرفوضة في اختبارات التحكم | منفذ |
| M1 | transport/checks/evidence/reports | fixtures موجبة وسالبة وقيود ظاهرة | منفذ ضمن الجدول أعلاه |
| M2 | OSINT provenance + local audit | لا طلب هدف ولا توسيع scope ولا نسب هوية | منفذ محدود المصادر |
| M3 | benchmark محكم ومراجعة مستقلة | precision وrecall لكل check مع false negatives وتكلفة طلبات | مخطط؛ suite الحالية ليست benchmark ميدانيًا |
| M4 | اكتشاف AST/OpenAPI/robots/sitemap أعمق | provenance لكل endpoint، إزالة تضخم دون ضياع اختلاف أمني | مخطط |
| M5 | tool broker مع عزل عمليات وشبكة | إثبات أن كل socket للأداة يخضع للحدود، لا مجرد flags | مخطط؛ imports فقط الآن |
| M6 | playbooks بحسب التقنية | شرط prerequisite + predicate خاص + controls + مختبر سالب | مخطط |
| M7 | browser/context analysis | إثبات execution الصحيح قبل ادعاء XSS، ضبط موارد المتصفح | مخطط |
| M8 | review queue/retest/report diff | حفظ قرار الباحث ودليله وعدم رفع severity تلقائيًا | مخطط |
| M9 | checkpoint/recovery/encryption | kill/restart tests، وعدم إعادة اختبارات خطرة، وسياسة retention | مخطط |
| M10 | pilot مصرح على أصول صغيرة/متوسطة | مقارنة baseline بنفس الميزانية ومراجعة بشرية للنتائج والفائت | لم يُجرَ |

الترتيب التالي الأفضل: **benchmark ثم اكتشاف أفضل ثم مراجعة/retest ثم أدوات إضافية**. إضافة 50 أداة قبل قياس الفائدة قد تعيد مشكلة المشروع السابق.

مقاييس النجاح: التغطية المنفذة لا المخططة، أسباب التعذر، صحة النتائج المراجعة، الحالات المعروفة التي فاتت، الطلبات لكل فرضية مقبولة، والقيمة الإضافية فوق baseline. لا معنى لنسبة دقة 100% على صفر نتائج مراجعة.

## 13. كيف يخدم قيمتك المهنية؟

استخدمه مع ملف أعمال قابل للتدقيق: تقرير مختبرك، حالة موجبة وأخرى سلبية، خطأ معروف وحدوده، remediation وretest. لا تقدمه كآلة مضمونة أو بديل عن فهم التطبيق. اتفق مع العميل على **منهجية وتغطية ومخرجات**، لا التزام «ثغرة واحدة على الأقل» قد لا تكون موجودة.

## 14. المراجع

- [OWASP WSTG Reporting](https://owasp.org/www-project-web-security-testing-guide/stable/5-Reporting/README): النطاق والقيود، شرح الأثر، إخفاء البيانات الحساسة والإصلاح. لا ندّعي تغطية WSTG كاملة.
- [Shodan InternetDB](https://book.shodan.io/developer-apis/internetdb/): قاعدة أسبوعية، وحقل vulns يضم verified وunverified؛ لا يكفي لإثبات ثغرة على التطبيق.
- [Cert Spotter API](https://sslmate.com/help/reference/ct_search_api_v1): شروط التقييم دون مصادقة، pagination ومعنى تواريخ الشهادات.
- [Wayback APIs](https://archive.org/help/wayback_api.php) و[CDX documentation](https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server): بيانات تاريخية وليست فحصًا حيًا.

**إذا لم نثبته، لا نسميه مثبتًا. وإذا لم نفحصه، لا نسميه آمنًا.**
