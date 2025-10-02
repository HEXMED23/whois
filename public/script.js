document.addEventListener('DOMContentLoaded', () => {
    const keywordInput = document.getElementById('keywordInput');
    const tldSelect = document.getElementById('tldSelect');
    const checkButton = document.getElementById('checkButton');
    const loadingDiv = document.getElementById('loading');
    const resultsDiv = document.getElementById('results');

    // قائمة النطاقات المدعومة (يجب أن تتطابق مع WHOIS_SERVERS في كود بايثون)
    const supportedTlds = ["com", "net", "org", "co", "xyz", "io", "online", "app"];

    // ملء قائمة النطاقات المنسدلة
    supportedTlds.forEach(tld => {
        const option = document.createElement('option');
        option.value = tld;
        option.textContent = `.${tld}`;
        tldSelect.appendChild(option);
    });

    checkButton.addEventListener('click', async () => {
        const keyword = keywordInput.value.trim();
        const tld = tldSelect.value;

        if (!keyword) {
            resultsDiv.innerHTML = '<p class="check-failed">الرجاء إدخال كلمة مفتاحية.</p>';
            resultsDiv.classList.remove('hidden');
            return;
        }

        loadingDiv.classList.remove('hidden');
        resultsDiv.classList.add('hidden');
        resultsDiv.innerHTML = ''; // مسح النتائج السابقة

        try {
            // ملاحظة: عند النشر على Vercel، مسار API هو '/api/check'
            // محليًا، قد يكون 'http://localhost:5000/check' إذا كنت تشغل Flask بشكل منفصل
            // Vercel يعالج توجيه '/api/*' تلقائيا إلى الدوال الخالية من الخادم في مجلد 'api'
            const response = await fetch('/api/check', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ keyword, tld }),
            });

            const result = await response.json();

            if (result.error) {
                resultsDiv.innerHTML = `<p class="check-failed">حدث خطأ: ${result.error}</p>`;
            } else if (result.available === true) {
                resultsDiv.innerHTML = `<p><strong class="available">✅ ${result.domain} متاح للتسجيل!</strong></p>`;
            } else if (result.available === false) {
                resultsDiv.innerHTML = `
                    <p><strong class="registered">❌ ${result.domain} مسجل بالفعل.</strong></p>
                    <p>المسجل: ${result.registrar}</p>
                    <p>تاريخ الإنشاء: ${result.creation_date}</p>
                    <p>تاريخ انتهاء الصلاحية: ${result.expiration_date}</p>
                `;
            } else {
                resultsDiv.innerHTML = `<p class="check-failed">⚠️ ${result.domain || 'النطاق'} - ${result.status}.</p>`;
                if (result.error) {
                    resultsDiv.innerHTML += `<p class="check-failed">خطأ: ${result.error}</p>`;
                }
            }
        } catch (error) {
            resultsDiv.innerHTML = `<p class="check-failed">حدث خطأ في الاتصال بالخادم: ${error.message}</p>`;
            console.error('Fetch error:', error);
        } finally {
            loadingDiv.classList.add('hidden');
            resultsDiv.classList.remove('hidden');
        }
    });
});
