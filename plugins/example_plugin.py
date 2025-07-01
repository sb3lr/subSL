# plugins/example_plugin.py
import asyncio
from typing import Set, Dict
import aiohttp
import logging

logger = logging.getLogger("SubSL.Plugin") # استخدام مسجل خاص بالإضافات

class ExamplePlugin:
    """
    مثال على إضافة لـ SubSL لجلب النطاقات الفرعية.
    هذه الإضافة لا تفعل شيئًا حقيقيًا بخلاف إظهار كيفية بناء المكون الإضافي.
    يمكنك استبدالها بمنطق لجلب البيانات من API خاص بك، أو ملف، إلخ.
    """
    def __init__(self, domain: str, session: aiohttp.ClientSession, config: Dict):
        self.domain = domain
        self.session = session
        self.config = config
        logger.info(f"تهيئة ExamplePlugin للنطاق: {domain}")

    async def gather_subdomains(self) -> Set[str]:
        """
        جلب النطاقات الفرعية باستخدام منطق هذه الإضافة.
        يجب أن تعيد مجموعة (Set) من سلاسل النطاقات الفرعية الكاملة (مثل "sub.domain.com").
        """
        results = set()
        logger.info(f"بدء جمع النطاقات الفرعية من ExamplePlugin للنطاق: {self.domain}")

        # --- منطق الإضافة هنا ---
        # على سبيل المثال، يمكن جلبها من API آخر أو من قاعدة بيانات خاصة.
        try:
            # مثال 1: إضافة بعض النطاقات الفرعية الوهمية أو المحددة مسبقًا
            results.add(f"test-plugin.{self.domain}")
            results.add(f"dev-plugin.{self.domain}")

            # مثال 2: لإضافة تتفاعل مع API خارجي (قم بإلغاء التعليق وتعديل حسب الحاجة)
            # افترض أن لديك مفتاح API مخصص لهذه الإضافة في ملف .env أو config.yaml
            # my_custom_key = self.config.get('api_keys',{}).get('my_custom_key')
            # if my_custom_key:
            #     url = f"https://api.example.com/subdomains?domain={self.domain}&key={my_custom_key}"
            #     async with self.session.get(url, timeout=self.config["timeout"]) as resp:
            #         if resp.status == 200:
            #             data = await resp.json()
            #             for sub in data.get("subdomains", []):
            #                 # تأكد من أن النطاق الفرعي ينتمي للدومين الرئيسي
            #                 if sub.endswith(self.domain) and sub != self.domain:
            #                     results.add(sub.lower())
            #                 elif not sub.endswith(self.domain): # إذا كان الـ API يعيد فقط الجزء الأول
            #                     results.add(f"{sub}.{self.domain}".lower())
            #         else:
            #             logger.warning(f"ExamplePlugin API response status: {resp.status} for {url}")
            # else:
            #     logger.warning("مفتاح 'my_custom_key' غير موجود لإضافة ExamplePlugin.")


            logger.info(f"ExamplePlugin انتهت من جمع {len(results)} نطاق فرعي.")

        except Exception as e:
            logger.error(f"خطأ في ExamplePlugin أثناء جمع البيانات: {e}")

        return results

# تذكر: هذا الملف هو مجرد إضافة. لكي يتم استخدامها، يجب استيرادها واستدعاؤها
# في الكود الأساسي لـ subsl.py كما وضحت لك في الرد السابق.
