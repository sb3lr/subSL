# إنشاء ملف README.md بالمحتوى الذي طلبته وحفظه في مسار يمكن تحميله
readme_content = """
# SubMax: أداة متقدمة لجمع وتحليل النطاقات الفرعية (Subdomain Enumeration)

![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
[![GitHub followers](https://img.shields.io/github/followers/sb3ly?style=social)](https://github.com/sb3ly)

---

## 🚀 نظرة عامة

**SubMax** هي أداة قوية ومتعددة الاستخدامات مصممة لجمع وتحليل النطاقات الفرعية (Subdomain Enumeration) لنطاق معين. تستخدم SubMax مزيجًا من تقنيات جمع المعلومات من المصادر المفتوحة (OSINT) وتقنية هجوم القوة الغاشمة (Brute-force) لاكتشاف أكبر عدد ممكن من النطاقات الفرعية النشطة. كما تتميز الأداة بقدرتها على اكتشاف احتمالية وجود هجمات Subdomain Takeover.

**الميزات الرئيسية:**

* **جمع OSINT:** تستفيد من مصادر متعددة مثل `crt.sh`, `SecurityTrails`, `GitHub`, `AlienVault OTX`, و `Shodan` (تتطلب مفاتيح API لبعض المصادر).
* **Brute-force:** توليد نطاقات فرعية محتملة باستخدام قائمة كلمات قوية.
* **فحص DNS متزامن:** استخدام `aiohttp` و `aiodns` للتحقق من وجود النطاقات الفرعية بكفاءة عالية وسرعة.
* **اكتشاف Subdomain Takeover:** التحقق تلقائيًا من النطاقات الفرعية الحية بحثًا عن مؤشرات Takeover بناءً على قائمة مضمنة من مزودي الخدمات الضعيفة.
* **تقارير مفصلة:** توليد تقارير بصيغ `JSON`, `CSV`, و `HTML` لسهولة التحليل والمشاركة.
* **واجهة ويب بسيطة (قيد التطوير):** لوحة تحكم أساسية لمتابعة التقدم (الميزات الكاملة قادمة).
* **إدارة الإعدادات:** تخصيص الأداة عبر ملف `config.yaml` ومتغيرات البيئة `.env`.

---

## 🛠️ المتطلبات الأساسية

تأكد من تثبيت Python 3.9 أو أحدث على نظامك.

---

## 📦 التثبيت

اتبع الخطوات التالية لتثبيت وتشغيل SubMax:

استنسخ المستودع (Clone the repository):

```bash
git clone https://github.com/sb3ly/SubMax.git
cd SubMax
أنشئ بيئة افتراضية (Virtual Environment) (موصى به):

bash

python3 -m venv venv
source venv/bin/activate  # لنظامي Linux/macOS
# venv\\Scripts\\activate  # لنظام Windows
تثبيت التبعيات (Install dependencies):

bash
pip install -r requirements.txt
إذا لم يكن ملف requirements.txt موجودًا بعد، قم بإنشائه بالمحتوى التالي ثم أعد تشغيل pip install -r requirements.txt:

nginx
aiohttp
aiodns
PyYAML
python-dotenv
fastapi
uvicorn
⚙️ الإعدادات

ملف config.yaml
قم بإنشاء أو تحديث ملف config.yaml في المجلد الرئيسي للمشروع بالإعدادات التالية:

yaml
# إعدادات SubMax الرئيسية

# عدد طلبات DNS المتزامنة. كلما زاد العدد، زادت السرعة.
concurrent_dns: 300

# المهلة القصوى بالثواني لطلبات HTTP و DNS.
timeout: 15

# فترة التوقف بالثواني في حال حدوث Rate Limit (غير مطبقة حالياً).
rate_limit_pause: 1

# أقصى عدد مرات إعادة المحاولة لطلبات API أو DNS الفاشلة (سيتم تطبيقها لاحقاً).
max_retries: 3
ملف .env (لمفاتيح API)
لتحقيق أقصى استفادة من SubMax، يوصى بالحصول على مفاتيح API للخدمات التالية. قم بإنشاء ملف باسم .env في المجلد الرئيسي للمشروع وضع مفاتيحك فيه. لا تشارك هذا الملف أبدًا!

ini
# ملف .env لمفاتيح API
# هذا الملف لا يجب أن يتم رفعه إلى مستودعات الكود العامة!

SECURITYTRAILS_API_KEY=<مفتاح SecurityTrails API الخاص بك هنا>
GITHUB_TOKEN=<مفتاح GitHub Personal Access Token الخاص بك هنا>
SHODAN_API_KEY=<مفتاح Shodan API الخاص بك هنا>
كيفية الحصول على مفاتيح API:

SecurityTrails: سجل في SecurityTrails للحصول على مفتاح API.

GitHub Token: أنشئ Personal Access Token من إعدادات حسابك في GitHub (Settings -> Developer settings -> Personal access tokens).

Shodan: سجل في Shodan للحصول على مفتاح API الخاص بك.

ملف wordlists.txt (لقائمة الكلمات)
قم بإنشاء ملف wordlists.txt في المجلد الرئيسي للمشروع. هذا الملف سيحتوي على الكلمات التي ستستخدمها الأداة في عملية الـ Brute-force. يمكنك العثور على قوائم كلمات كبيرة وموثوقة عبر الإنترنت أو إنشاء قائمة خاصة بك.

🚀 الاستخدام
بمجرد إعداد ملفات config.yaml, .env, و wordlists.txt, يمكنك تشغيل SubMax من سطر الأوامر:

bash
python3 submax.py <اسم_النطاق>
مثال:

bash
python3 submax.py example.com
تشغيل واجهة الويب (اختياري)
يمكنك تشغيل واجهة الويب جنبًا إلى جنب مع عملية الفحص. ستعرض واجهة الويب حالة التقدم الحالية:

bash
python3 submax.py example.com --web
بعد تشغيل هذا الأمر، ستكون واجهة الويب متاحة على: http://localhost:8000

📊 التقارير
بعد اكتمال عملية الفحص، ستقوم SubMax بإنشاء ثلاثة أنواع من التقارير في المجلد الرئيسي:

report_<domain>_<timestamp>.json: تقرير JSON مفصل يحتوي على جميع البيانات المكتشفة.

report_<domain>_<timestamp>.csv: تقرير CSV لسهولة التحليل في جداول البيانات.

report_<domain>_<timestamp>.html: تقرير HTML بتنسيق سهل القراءة لعرض النتائج في المتصفح.

🤝 المساهمة
نرحب بالمساهمات! إذا كان لديك أي اقتراحات أو تحسينات أو إصلاحات للأخطاء، فلا تتردد في فتح مشكلة (Issue) أو إرسال طلب سحب (Pull Request).

📄 الترخيص
هذا المشروع مرخص بموجب ترخيص MIT. انظر ملف LICENSE لمزيد من التفاصيل.

👤 المؤلف
سعيد (Sa3ed)
GitHub: sb3ly

