"""
اختبار سريع: هل Railway يسمح بالاتصال بـ MEGA API؟
شغّل هذا على Railway أولاً
"""
import requests, json

# اختبار الاتصال بـ MEGA API
try:
    r = requests.post(
        'https://g.api.mega.co.nz/cs',
        params={'id': 0},
        json=[{'a': 'ping'}],
        timeout=10
    )
    print(f"Status: {r.status_code}")
    print(f"Content: {r.text[:200]}")
    if r.status_code == 200:
        print("✅ MEGA API متاح من Railway")
    elif r.status_code == 402:
        print("❌ Railway محجوب من MEGA — نحتاج بديل")
    else:
        print(f"⚠️ كود غير متوقع: {r.status_code}")
except Exception as e:
    print(f"❌ فشل الاتصال: {e}")
