"""
Defensive OSINT Bot — Personal Data Breach Checker
====================================================
Purpose: Let a user check whether THEIR OWN email or password has
appeared in a known data breach, using the legitimate
Have I Been Pwned (HIBP) service.

This bot does NOT look up other people's data. It is meant strictly
for personal security hygiene.

Setup:
1. pip install -r requirements.txt
2. Create a bot with @BotFather on Telegram, get the token.
3. (Optional but recommended for email checks) Get a HIBP API key:
   https://haveibeenpwned.com/API/Key  (paid, ~$3.50/month)
   Password checks work with NO key at all (free, k-anonymity model).
4. Set environment variables:
   export TELEGRAM_BOT_TOKEN="your_token_here"
   export HIBP_API_KEY="your_hibp_key_here"   # optional
5. Run: python bot.py
"""

import os
import hashlib
import logging

import requests
from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ContextTypes,
)

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
HIBP_API_KEY = os.environ.get("HIBP_API_KEY")  # None => email check disabled
NUMVERIFY_API_KEY = os.environ.get("NUMVERIFY_API_KEY")  # None => phone check disabled

HIBP_BREACH_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{}"
HIBP_PASSWORD_URL = "https://api.pwnedpasswords.com/range/{}"
NUMVERIFY_URL = "http://apilayer.net/api/validate"

DISCLAIMER = (
    "⚠️ هذا البوت مخصص فقط للتحقق من بياناتك الشخصية (بريدك أو كلمة مرورك).\n"
    "لا تستخدمه للتحقق من بيانات أشخاص آخرين بدون إذنهم."
)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 أهلاً! أنا بوت فحص أمني دفاعي.\n\n"
        "الأوامر المتاحة:\n"
        "/checkemail <بريدك> — تحقق هل بريدك ظهر في تسريب بيانات\n"
        "/checkpassword <كلمة المرور> — تحقق هل كلمة مرورك مسربة (آمن، لا تُرسل كاملة)\n"
        "/checkphone <رقمك> — تحقق من صحة رقم هاتفك (الدولة، المشغّل)\n"
        "/securitycheck — خطوات تتأكد فيها بنفسك من أمان حسابك على تليجرام\n\n"
        f"{DISCLAIMER}"
    )


async def check_email(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not HIBP_API_KEY:
        await update.message.reply_text(
            "❌ فحص البريد الإلكتروني معطّل حالياً لأنه يحتاج مفتاح HIBP API "
            "(خدمة مدفوعة). يمكنك استخدام /checkpassword مجاناً، أو الحصول "
            "على مفتاح من https://haveibeenpwned.com/API/Key وإضافته "
            "كمتغيّر بيئة HIBP_API_KEY."
        )
        return

    if not context.args:
        await update.message.reply_text("استخدم الأمر هكذا:\n/checkemail your@email.com")
        return

    email = context.args[0].strip()
    await update.message.reply_text(f"🔍 جارٍ التحقق من: {email} ...")

    try:
        resp = requests.get(
            HIBP_BREACH_URL.format(email),
            headers={
                "hibp-api-key": HIBP_API_KEY,
                "user-agent": "Personal-Security-Check-Bot",
            },
            timeout=15,
        )
    except requests.RequestException as e:
        logger.error("HIBP request failed: %s", e)
        await update.message.reply_text("⚠️ حدث خطأ أثناء الاتصال بالخدمة. حاول لاحقاً.")
        return

    if resp.status_code == 200:
        breaches = resp.json()
        names = ", ".join(b["Name"] for b in breaches)
        await update.message.reply_text(
            f"🚨 بريدك ظهر في {len(breaches)} تسريب/تسريبات:\n{names}\n\n"
            "نصيحة: غيّر كلمة المرور فوراً في هذه المواقع وفعّل التحقق بخطوتين (2FA)."
        )
    elif resp.status_code == 404:
        await update.message.reply_text("✅ بشرى سارة! بريدك لم يظهر في أي تسريب معروف.")
    elif resp.status_code == 429:
        await update.message.reply_text("⏳ محاولات كثيرة، انتظر قليلاً وحاول مرة أخرى.")
    else:
        await update.message.reply_text(f"⚠️ خطأ غير متوقع (كود {resp.status_code}).")


async def check_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Uses the k-anonymity model: only the first 5 characters of the
    SHA-1 hash are sent to the API — the full password NEVER leaves
    the user's device/bot in plaintext or full hash form.
    """
    if not context.args:
        await update.message.reply_text("استخدم الأمر هكذا:\n/checkpassword YourPassword123")
        return

    password = " ".join(context.args)
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        resp = requests.get(HIBP_PASSWORD_URL.format(prefix), timeout=15)
    except requests.RequestException as e:
        logger.error("HIBP password request failed: %s", e)
        await update.message.reply_text("⚠️ حدث خطأ أثناء الاتصال بالخدمة. حاول لاحقاً.")
        return

    if resp.status_code != 200:
        await update.message.reply_text(f"⚠️ خطأ غير متوقع (كود {resp.status_code}).")
        return

    count = 0
    for line in resp.text.splitlines():
        hash_suffix, hash_count = line.split(":")
        if hash_suffix == suffix:
            count = int(hash_count)
            break

    # Try to delete the user's message so the password isn't left visible in chat
    try:
        await update.message.delete()
    except Exception:
        pass

    if count > 0:
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=(
                f"🚨 كلمة المرور هذه ظهرت {count:,} مرة في تسريبات بيانات معروفة.\n"
                "غيّرها فوراً في أي مكان تستخدمها!"
            ),
        )
    else:
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text="✅ لم تظهر كلمة المرور هذه في أي تسريب معروف. (استمر باستخدام كلمات مرور قوية وفريدة)",
        )


async def check_phone(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Validates a phone number's format/carrier/country using NumVerify
    (legitimate phone-validation service). This does NOT check breach
    databases — there is no trustworthy public breach-lookup API for
    phone numbers, unlike email (HIBP) or passwords. Services that
    claim to do this are almost always unvetted "probiv" tools and are
    not used here.
    """
    if not NUMVERIFY_API_KEY:
        await update.message.reply_text(
            "❌ فحص الهاتف معطّل حالياً لأنه يحتاج مفتاح NumVerify API "
            "(له باقة مجانية بحد شهري). احصل على مفتاح من "
            "https://numverify.com وأضفه كمتغيّر بيئة NUMVERIFY_API_KEY.\n\n"
            "ملاحظة: هذا الفحص يتحقق فقط من صحة تنسيق الرقم والدولة والمشغّل، "
            "وليس هناك خدمة موثوقة تفحص 'تسريب' أرقام الهواتف تحديداً."
        )
        return

    if not context.args:
        await update.message.reply_text("استخدم الأمر هكذا:\n/checkphone +9665XXXXXXXX")
        return

    phone = context.args[0].strip()
    await update.message.reply_text(f"🔍 جارٍ التحقق من: {phone} ...")

    try:
        resp = requests.get(
            NUMVERIFY_URL,
            params={"access_key": NUMVERIFY_API_KEY, "number": phone},
            timeout=15,
        )
    except requests.RequestException as e:
        logger.error("NumVerify request failed: %s", e)
        await update.message.reply_text("⚠️ حدث خطأ أثناء الاتصال بالخدمة. حاول لاحقاً.")
        return

    data = resp.json()
    if not data.get("valid"):
        await update.message.reply_text(
            "⚠️ الرقم غير صالح أو التنسيق غير صحيح. تأكد من كتابته مع رمز الدولة (مثال: +966...)."
        )
        return

    await update.message.reply_text(
        "📱 نتيجة الفحص:\n"
        f"الدولة: {data.get('country_name', 'غير معروف')}\n"
        f"المشغّل: {data.get('carrier') or 'غير متوفر'}\n"
        f"نوع الخط: {data.get('line_type') or 'غير متوفر'}\n\n"
        "✅ هذا فقط تحقق من صحة الرقم، وليس فحص تسريب بيانات."
    )


async def security_check(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Points the user to Telegram's OWN built-in security tools — the
    only real source of truth for whether their account is compromised.
    """
    await update.message.reply_text(
        "🔐 خطوات تتأكد فيها بنفسك من أمان حسابك على تليجرام:\n\n"
        "1️⃣ اذهب إلى: Settings → Devices (الإعدادات → الأجهزة)\n"
        "   شوف كل الجلسات المتصلة بحسابك. أي جهاز ما تعرفه؟ اضغط عليه واختر "
        "'Terminate Session' لإنهائه فوراً.\n\n"
        "2️⃣ فعّل التحقق بخطوتين:\n"
        "   Settings → Privacy and Security → Two-Step Verification\n\n"
        "3️⃣ راجع من يقدر يضيفك بمجموعات:\n"
        "   Settings → Privacy and Security → Groups & Channels\n\n"
        "4️⃣ لا تشارك كود التفعيل (OTP) اللي يوصلك عبر SMS مع أي أحد أبداً، "
        "حتى لو ادّعى أنه من تليجرام.\n\n"
        "هذي الخطوات داخل تطبيق تليجرام نفسه، وهي الطريقة الوحيدة الموثوقة "
        "لمعرفة هل حسابك مخترق أو لا — ما فيه بوت خارجي يقدر يعرف هذي المعلومة نيابة عنك."
    )


def main():
    if not BOT_TOKEN:
        raise SystemExit(
            "❌ ضع متغير البيئة TELEGRAM_BOT_TOKEN قبل التشغيل.\n"
            "مثال: export TELEGRAM_BOT_TOKEN='123456:ABC-...'"
        )

    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("checkemail", check_email))
    app.add_handler(CommandHandler("checkpassword", check_password))
    app.add_handler(CommandHandler("checkphone", check_phone))
    app.add_handler(CommandHandler("securitycheck", security_check))

    logger.info("Bot starting (polling)...")
    app.run_polling()


if __name__ == "__main__":
    main()
