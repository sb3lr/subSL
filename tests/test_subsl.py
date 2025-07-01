# tests/test_subsl.py
import pytest
import sys
import os
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

# أضف مسار المشروع إلى sys.path لكي تتمكن من استيراد subsl
# هذا يسمح للاختبارات بالعثور على ملف subsl.py الرئيسي
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# استيراد الدوال التي نريد اختبارها من subsl.py
# تأكد من أن هذه الاستيرادات تتطابق مع أسماء الدوال في subsl.py
from subsl import (
    sanitize_domain,
    read_wordlist,
    generate_bruteforce,
    OSINTCollector,
    DNSResolver,
    load_config, # تم تضمينها لاختبار وظيفة mock_config
    ExamplePlugin # لاستيراد الإضافة إذا أردت اختبارها مباشرة
)

# Mock config for tests
@pytest.fixture
def mock_config():
    """
    إعداد Mock config للاختبارات لتجنب الاعتماد على config.yaml الحقيقي
    وللسماح بتعريف مفاتيح API وهمية.
    """
    return {
        "concurrent_dns": 10,
        "concurrent_http": 10, # أضفت هذه القيمة لتماشي مع الاستخدام العام
        "timeout": 5,
        "http_timeout": 5, # أضفت هذه القيمة لتماشي مع الاستخدام العام
        "rate_limit_pause": 1,
        "max_retries": 1,
        "takeover_providers_url": "http://mock.takeover.url", # قد لا تكون هذه الخاصية مستخدمة في الكود المحدث، ولكنها موجودة هنا للموك.
        "api_keys": {
            "securitytrails": "mock_st_key",
            "github": "mock_gh_key",
            "shodan": "mock_sh_key",
            "my_custom_key": "mock_custom_key" # مثال لمفتاح API خاص بإضافة
        }
    }

# --- اختبار دوال المساعدة العامة (General Helper Functions) ---

def test_sanitize_domain():
    """اختبار دالة sanitize_domain لتنظيف أسماء النطاقات."""
    assert sanitize_domain("example.com") == "example.com"
    assert sanitize_domain("  EXAMPLE.COM/ ") == "example.com"
    assert sanitize_domain("https://www.EXAMPLE.COM") == "www.example.com"
    assert sanitize_domain("http://sub.example.com/") == "sub.example.com"
    assert sanitize_domain("sub.domain.com") == "sub.domain.com"
    assert sanitize_domain("  test.com  ") == "test.com"

def test_read_wordlist(tmp_path):
    """
    اختبار دالة read_wordlist لقراءة قائمة الكلمات من ملف.
    tmp_path هو fixture من pytest ينشئ دليلاً مؤقتًا للاختبار.
    """
    # إنشاء ملف wordlist مؤقت للاختبار
    test_wordlist_content = "word1\n#comment\nword2\n\nword3\n word4 "
    wordlist_path = tmp_path / "test_wordlist.txt"
    wordlist_path.write_text(test_wordlist_content)

    words = read_wordlist(str(wordlist_path))
    assert words == ["word1", "word2", "word3", "word4"] # يجب أن يقوم بالـ strip للكلمات

    # اختبار ملف غير موجود
    words_non_existent = read_wordlist("non_existent_file.txt")
    assert words_non_existent == []

def test_generate_bruteforce():
    """اختبار دالة generate_bruteforce لتوليد النطاقات الفرعية."""
    wordlist = ["test", "dev"]
    domain = "example.com"
    generated = generate_bruteforce(wordlist, domain) # لا يوجد max_length في الكود المحدث

    # التحقق من بعض النطاقات المتوقعة (بناءً على سلوكك الموضح سابقاً)
    assert "test.example.com" in generated
    assert "dev.example.com" in generated

    # الكود الموضح لـ generate_bruteforce لا يقوم بتراكيب مثل testdev.example.com
    # أو test-dev.example.com أو test.dev.example.com بشكل تلقائي
    # إذا كنت تتوقع هذه النتائج، يجب تعديل generate_bruteforce نفسها لتوليدها.
    # بناءً على الكود الذي تم توفيره في subsl.py، ستكون هذه النتائج غير موجودة.
    # التأكد من عدم وجود تراكيب غير مدعومة من الدالة الحالية
    assert "testdev.example.com" not in generated
    assert "test-dev.example.com" not in generated
    assert "test.dev.example.com" not in generated


# --- اختبار OSINTCollector ---

@pytest.mark.asyncio
async def test_osint_collector_crtsh(mock_config):
    """اختبار جلب النطاقات الفرعية من crt.sh."""
    # Mock aiohttp.ClientSession
    mock_session = MagicMock()
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.json.return_value = [{"name_value": "sub1.test.com\nsub2.test.com"}, {"name_value": "*.test.com\nanother.test.com"}]
    mock_session.get.return_value.__aenter__.return_value = mock_response

    collector = OSINTCollector("test.com", mock_session, mock_config)
    results = await collector.from_crtsh()

    assert "sub1.test.com" in results
    assert "sub2.test.com" in results
    assert "another.test.com" in results
    assert "*.test.com" not in results # يجب أن يتم تجاهل Wildcard
    assert len(results) == 3

@pytest.mark.asyncio
async def test_osint_collector_securitytrails(mock_config):
    """اختبار جلب النطاقات الفرعية من SecurityTrails."""
    mock_session = MagicMock()
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.json.return_value = {"subdomains": ["sub3", "sub4"]}
    mock_session.get.return_value.__aenter__.return_value = mock_response

    collector = OSINTCollector("test.com", mock_session, mock_config)
    results = await collector.from_securitytrails()

    assert "sub3.test.com" in results
    assert "sub4.test.com" in results
    assert len(results) == 2
    mock_session.get.assert_called_with(
        "https://api.securitytrails.com/v1/domain/test.com/subdomains",
        headers={"APIKEY": "mock_st_key"},
        timeout=mock_config["timeout"]
    )

@pytest.mark.asyncio
async def test_osint_collector_github(mock_config):
    """اختبار جلب النطاقات الفرعية من GitHub."""
    mock_session = MagicMock()
    mock_response = AsyncMock()
    mock_response.status = 200
    # مثال لنتيجة GitHub قد تحتوي على نطاق فرعي في المسار
    mock_response.json.return_value = {"items": [{"path": "config/sub.test.com.yaml"}]}
    mock_session.get.return_value.__aenter__.return_value = mock_response

    collector = OSINTCollector("test.com", mock_session, mock_config)
    results = await collector.from_github()

    assert "config/sub.test.com.yaml" in results # الكود الحالي يضيف المسار كاملاً
    assert len(results) == 1
    mock_session.get.assert_called_with(
        "https://api.github.com/search/code?q=test.com+extension:yaml",
        headers={"Authorization": "token mock_gh_key"},
        timeout=mock_config["timeout"]
    )

@pytest.mark.asyncio
async def test_osint_collector_alienvault(mock_config):
    """اختبار جلب النطاقات الفرعية من AlienVault OTX."""
    mock_session = MagicMock()
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.json.return_value = {"passive_dns": [{"hostname": "sub5.test.com"}, {"hostname": "notrelated.com"}]}
    mock_session.get.return_value.__aenter__.return_value = mock_response

    collector = OSINTCollector("test.com", mock_session, mock_config)
    results = await collector.from_alienvault()

    assert "sub5.test.com" in results
    assert "notrelated.com" not in results # يجب أن يتم تصفية النطاقات غير ذات الصلة
    assert len(results) == 1

@pytest.mark.asyncio
async def test_osint_collector_shodan(mock_config):
    """اختبار جلب النطاقات الفرعية من Shodan."""
    mock_session = MagicMock()
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.json.return_value = {"subdomains": ["sub6", "sub7"]}
    mock_session.get.return_value.__aenter__.return_value = mock_response

    collector = OSINTCollector("test.com", mock_session, mock_config)
    results = await collector.from_shodan()

    assert "sub6.test.com" in results
    assert "sub7.test.com" in results
    assert len(results) == 2
    mock_session.get.assert_called_with(
        "https://api.shodan.io/dns/domain/test.com",
        params={"key": "mock_sh_key"},
        timeout=mock_config["timeout"]
    )

@pytest.mark.asyncio
async def test_osint_collector_gather_all(mock_config):
    """اختبار دالة gather_all التي تجمع من جميع المصادر والإضافات."""
    mock_session = MagicMock()
    collector = OSINTCollector("test.com", mock_session, mock_config)

    # Mock كل دوال جلب OSINT والإضافة لتقديم نتائج محددة
    with patch.object(collector, 'from_crtsh', new=AsyncMock(return_value={"sub1.test.com"})):
        with patch.object(collector, 'from_securitytrails', new=AsyncMock(return_value={"sub2.test.com"})):
            with patch.object(collector, 'from_github', new=AsyncMock(return_value={"sub3.test.com"})):
                with patch.object(collector, 'from_alienvault', new=AsyncMock(return_value={"sub4.test.com"})):
                    with patch.object(collector, 'from_shodan', new=AsyncMock(return_value={"sub5.test.com"})):
                        # Mock الإضافة أيضًا
                        with patch('subsl.ExamplePlugin.gather_subdomains', new=AsyncMock(return_value={"plugin.test.com"})):
                            all_results = await collector.gather_all()

                            expected_results = {
                                "sub1.test.com", "sub2.test.com", "sub3.test.com",
                                "sub4.test.com", "sub5.test.com", "plugin.test.com"
                            }
                            assert all_results == expected_results
                            assert len(all_results) == len(expected_results)


# --- اختبار DNSResolver ---

@pytest.mark.asyncio
async def test_dns_resolver_resolve():
    """اختبار دالة resolve لحل IP."""
    resolver = DNSResolver(concurrency=1)

    # Mock aiodns.DNSResolver.gethostbyname
    with patch('aiodns.DNSResolver.gethostbyname') as mock_gethostbyname:
        mock_gethostbyname.return_value = MagicMock(addresses=["192.0.2.1"])

        ip = await resolver.resolve("test.example.com")
        assert ip == "192.0.2.1"
        mock_gethostbyname.assert_called_once_with("test.example.com", os.sys.socket.AF_INET)

        # تحقق من التخزين المؤقت (cache)
        mock_gethostbyname.reset_mock() # إعادة تعيين الـ mock لتتبع الاستدعاءات الجديدة
        ip_from_cache = await resolver.resolve("test.example.com")
        assert ip_from_cache == "192.0.2.1"
        mock_gethostbyname.assert_not_called() # لم يتم استدعاؤه لأنه من الكاش

@pytest.mark.asyncio
async def test_dns_resolver_get_cname():
    """اختبار دالة get_cname لجلب CNAME."""
    resolver = DNSResolver(concurrency=1)

    # Mock aiodns.DNSResolver.query
    with patch('aiodns.DNSResolver.query') as mock_query:
        mock_query.return_value = [MagicMock(host="target.service.com")]

        cname = await resolver.get_cname("sub.example.com")
        assert cname == "target.service.com"
        mock_query.assert_called_once_with("sub.example.com", 'CNAME')

        # تحقق من التخزين المؤقت (cache)
        mock_query.reset_mock()
        cname_from_cache = await resolver.get_cname("sub.example.com")
        assert cname_from_cache == "target.service.com"
        mock_query.assert_not_called()

@pytest.mark.asyncio
async def test_dns_resolver_check_takeover():
    """اختبار دالة check_takeover لاكتشاف الاستيلاء المحتمل."""
    resolver = DNSResolver(concurrency=1)
    # استخدام جزء صغير من قائمة مزودي الاستيلاء للاختبار
    takeover_providers = {"gh-pages.github.io": "GitHub Pages", "s3-website-us-east-1.amazonaws.com": "AWS S3"}

    # Mock get_cname
    with patch.object(resolver, 'get_cname', new=AsyncMock()) as mock_get_cname:
        # حالة CNAME موجودة وتطابق Takeover
        mock_get_cname.return_value = "something.gh-pages.github.io"
        takeover_info = await resolver.check_takeover("sub1.example.com", takeover_providers)
        assert takeover_info == {"subdomain": "sub1.example.com", "cname": "something.gh-pages.github.io", "provider": "GitHub Pages"}

        # حالة CNAME موجودة ولا تطابق Takeover
        mock_get_cname.return_value = "valid.target.com"
        takeover_info = await resolver.check_takeover("sub2.example.com", takeover_providers)
        assert takeover_info is None

        # حالة لا يوجد CNAME
        mock_get_cname.return_value = None
        takeover_info = await resolver.check_takeover("sub3.example.com", takeover_providers)
        assert takeover_info is None

# --- اختبار ExamplePlugin ---

@pytest.mark.asyncio
async def test_example_plugin_gather_subdomains(mock_config):
    """اختبار دالة gather_subdomains في ExamplePlugin."""
    mock_session = MagicMock() # لا نحتاج جلسة حقيقية لهذه الإضافة البسيطة
    plugin = ExamplePlugin("test.com", mock_session, mock_config)
    results = await plugin.gather_subdomains()

    assert "test-plugin.test.com" in results
    assert "dev-plugin.test.com" in results
    assert len(results) == 2

    # يمكن إضافة اختبارات أكثر تعقيدًا هنا إذا أصبحت الإضافة تتفاعل مع API
    # على سبيل المثال:
    # mock_response = AsyncMock()
    # mock_response.status = 200
    # mock_response.json.return_value = {"subdomains": ["api-sub1", "api-sub2"]}
    # mock_session.get.return_value.__aenter__.return_value = mock_response
    #
    # plugin = ExamplePlugin("api.com", mock_session, mock_config)
    # results = await plugin.gather_subdomains()
    # assert "api-sub1.api.com" in results
    # assert "api-sub2.api.com" in results
