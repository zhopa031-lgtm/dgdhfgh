/* ============================================================================
   VERSTAK — Telegram-бот приёма заявок с сайта.
   ----------------------------------------------------------------------------
   Как это работает:
     1. Форма заявки на сайте (секция «Контакты» в index.html) отправляет
        POST-запрос с JSON на http://localhost:3000/api/submit (адрес задан
        в js/config.js → formEndpoint).
     2. Этот сервер проверяет: домен сайта (CORS), частоту запросов с одного
        IP (5 в минуту), корректность данных и honeypot-ловушку для ботов.
     3. Заявка уходит вам в Telegram сообщением вида:
          🆕 Новая заявка с сайта
          👤 Имя: …   📞 Контакт: …   📦 Тип проекта: …
          📝 Описание: …
     4. Сайт получает ответ { success: true } и показывает посетителю
        подтверждение. При любом сбое — понятная ошибка и запасной путь
        «напишите напрямую @angcorupt».

   НАСТРОЙКА — единственный файл .env рядом (см. комментарии в нём):
     BOT_TOKEN — токен от @BotFather  ★ та самая одна строчка для правки
     CHAT_ID   — ваш Telegram ID (уже вписан: 1047449816)

   ЗАПУСК:  npm install  →  npm start   (в этой папке, Node.js >= 18)
   ============================================================================ */

require("dotenv").config(); // загружаем настройки из файла .env в process.env
const express = require("express");
const cors = require("cors");

/* ----------------------------------------------------------------------------
   1. КОНФИГУРАЦИЯ ИЗ .env
   ---------------------------------------------------------------------------- */

const PORT = process.env.PORT || 3000;
const BOT_TOKEN = process.env.BOT_TOKEN || "";
const CHAT_ID = process.env.CHAT_ID || "";

// Список доменов сайта, которым разрешено слать заявки: парсим строку из .env.
// Особое значение "null" — это сайт, открытый двойным кликом по index.html
// (браузер помечает такие запросы Origin: null), оставляем ради удобства.
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean);

// Предупреждаем в консоли, если токен ещё не вставлен: сервер стартует
// и корректно валидирует заявки, но отправить их в Telegram не сможет —
// сайт в этом случае честно предложит посетителю написать напрямую.
if (!BOT_TOKEN || BOT_TOKEN.includes("ВСТАВЬТЕ")) {
  console.warn("[warn] BOT_TOKEN не задан (это заглушка) — впишите токен от @BotFather в файл bot/.env");
}
if (!CHAT_ID) {
  console.warn("[warn] CHAT_ID не задан — некому отправлять заявки.");
}

/* ----------------------------------------------------------------------------
   2. RATE LIMITER (в памяти, без внешних сервисов)
   ----------------------------------------------------------------------------
   Скользящее окно: для каждого IP храним временные метки запросов за последнюю
   минуту. Больше MAX_REQ_PER_WINDOW за окно → ответ 429. Старые записи чистим
   лениво при каждом запросе и фоновым интервалом, чтобы Map не разрасталась. */

const WINDOW_MS = 60 * 1000;   // окно: 1 минута
const MAX_REQ_PER_WINDOW = 5;  // максимум 5 заявок в минуту с одного IP
const ipHits = new Map();      // Map<ip, массив временных меток>

function rateLimiter(req, res, next) {
  const ip = req.ip || "unknown";
  const now = Date.now();

  // оставляем только «свежие» запросы этого IP (за последние 60 секунд)
  const hits = (ipHits.get(ip) || []).filter((t) => now - t < WINDOW_MS);

  if (hits.length >= MAX_REQ_PER_WINDOW) {
    // сколько секунд до освобождения слота — отдаём в заголовке Retry-After
    const retryAfterSec = Math.ceil((hits[0] + WINDOW_MS - now) / 1000);
    res.set("Retry-After", String(Math.max(1, retryAfterSec)));
    return res.status(429).json({
      success: false,
      error: "Слишком много заявок подряд. Подождите минуту и попробуйте снова, либо напишите напрямую в Telegram @angcorupt.",
    });
  }

  hits.push(now);
  ipHits.set(ip, hits);
  next();
}

// Фоновая чистка Map раз в минуту; unref — чтобы таймер не мешал процессу
// корректно завершиться по Ctrl+C.
setInterval(() => {
  const now = Date.now();
  for (const [ip, hits] of ipHits) {
    const fresh = hits.filter((t) => now - t < WINDOW_MS);
    if (fresh.length === 0) ipHits.delete(ip);
    else ipHits.set(ip, fresh);
  }
}, WINDOW_MS).unref();

/* ----------------------------------------------------------------------------
   3. ВАЛИДАЦИЯ И ЭКРАНИРОВАНИЕ
   ---------------------------------------------------------------------------- */

// Белый список типов проекта — ровно те значения, что в <select> на сайте
// (index.html, поле fType). Любое другое значение → ошибка 400.
const PROJECT_TYPES = [
  "Сайт",
  "Лендинг",
  "Веб-приложение",
  "Автоматизация",
  "Telegram-бот",
  "Интеграции",
  "MVP",
  "Другое",
];

const LIMITS = {
  name: { min: 2, max: 100 },         // имя: от 2 до 100 символов
  contact: { min: 3, max: 150 },      // контакт: от 3 до 150 символов
  message: { min: 5, max: 3000 },     // описание задачи: от 5 до 3000 символов
};

// Экранируем HTML-спецсимволы (&, <, >): parse_mode HTML в Telegram сломается,
// если в тексте заявки встретится «сырой» тег, подставленный злоумышленником.
function escapeHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// Возвращает текст ошибки валидации или null, если всё в порядке.
function validate(body) {
  const { name, contact, type, message } = body;

  // — всё должно быть строками (защита от JSON с числами/объектами/массивами)
  if (typeof name !== "string" || typeof contact !== "string" ||
      typeof type !== "string" || typeof message !== "string") {
    return "Некорректный формат данных: все поля должны быть строками.";
  }

  const nameT = name.trim();
  const contactT = contact.trim();
  const messageT = message.trim();

  // — минимальные и максимальные длины (как в клиентской валидации сайта)
  if (nameT.length < LIMITS.name.min) {
    return `Имя слишком короткое — минимум ${LIMITS.name.min} символа.`;
  }
  if (nameT.length > LIMITS.name.max) {
    return `Имя слишком длинное — максимум ${LIMITS.name.max} символов.`;
  }
  if (contactT.length < LIMITS.contact.min) {
    return `Контакт слишком короткий — минимум ${LIMITS.contact.min} символа.`;
  }
  if (contactT.length > LIMITS.contact.max) {
    return `Контакт слишком длинный — максимум ${LIMITS.contact.max} символов.`;
  }
  if (messageT.length < LIMITS.message.min) {
    return `Описание слишком короткое — минимум ${LIMITS.message.min} символов.`;
  }
  if (messageT.length > LIMITS.message.max) {
    return `Описание слишком длинное — максимум ${LIMITS.message.max} символов.`;
  }

  // — тип проекта строго из списка
  if (!PROJECT_TYPES.includes(type)) {
    return "Выберите тип проекта из предложенного списка.";
  }

  return null;
}

/* ----------------------------------------------------------------------------
   4. ОТПРАВКА В TELEGRAM (Bot API: sendMessage, HTML, таймаут 8 секунд)
   ---------------------------------------------------------------------------- */

async function sendToTelegram(name, contact, type, message, meta) {
  // Текст заявки. Пользовательские поля экранированы; type берётся из белого
  // списка, поэтому безопасен как есть.
  let text =
    "🆕 <b>Новая заявка с сайта</b>\n\n" +
    "👤 <b>Имя:</b> " + escapeHtml(name) + "\n" +
    "📞 <b>Контакт:</b> " + escapeHtml(contact) + "\n" +
    "📦 <b>Тип проекта:</b> " + type + "\n\n" +
    "📝 <b>Описание:</b>\n" + escapeHtml(message);

  // Техническая приписка: с какой страницы и когда пришла заявка (meta
  // формирует сам сайт; если её нет — строка просто не добавляется).
  if (meta && typeof meta === "object" && typeof meta.page === "string") {
    const when = (typeof meta.date === "string" && meta.date)
      ? meta.date.replace("T", " ").slice(0, 19)
      : "";
    text += "\n\n🔗 <i>Страница: " + escapeHtml(meta.page) +
      (when ? " · " + escapeHtml(when) : "") + "</i>";
  }

  // AbortController + setTimeout — жёсткий таймаут 8 секунд: если Telegram
  // завис или недоступен, отменяем запрос и отдаём сайту понятную ошибку.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);

  try {
    const res = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: CHAT_ID,
        text: text,
        parse_mode: "HTML",
        disable_web_page_preview: true,
      }),
      signal: controller.signal,
    });

    // Telegram отвечает JSON-ом вида { ok: true/false, description }
    const data = await res.json().catch(() => null);

    if (!res.ok || !data || data.ok !== true) {
      const reason = (data && data.description) || `HTTP ${res.status}`;
      throw new Error(reason);
    }
    return true;
  } finally {
    clearTimeout(timer); // в любом случае снимаем таймер
  }
}

/* ----------------------------------------------------------------------------
   5. ПРИЛОЖЕНИЕ EXPRESS
   ---------------------------------------------------------------------------- */

const app = express();

// Доверяем одному уровню прокси (Render/Railway/Nginx): тогда req.ip вернёт
// реальный IP клиента из заголовка X-Forwarded-For, а не IP прокси — без этого
// rate limiting считал бы всех посетителей одним IP.
app.set("trust proxy", 1);

// CORS с белым списком из .env:
//   • Origin из списка (или "null" — сайт с файловой системы) — разрешаем;
//   • запросы БЕЗ Origin (curl, Postman) — разрешаем всегда;
//   • чужой Origin — просто не выдаём CORS-заголовки (браузер заблокирует
//     ответ), а на уровне эндпоинта ниже — ещё и явный отказ 403.
app.use(cors({
  origin(origin, callback) {
    if (!origin) return callback(null, true);                     // curl/Postman
    if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    return callback(null, false);                                 // чужой домен
  },
}));

// Разбираем JSON-тело максимум 16 КБ — для заявки с запасом, а лимит не даёт
// забить сервер мусорными гигантскими запросами.
app.use(express.json({ limit: "16kb" }));

/* --- GET /health — проверка живости сервера (для деплоя и мониторинга) --- */
app.get("/health", (req, res) => {
  res.json({ ok: true, uptime: Math.round(process.uptime()) });
});

/* --- POST /api/submit — главный эндпоинт: приём заявки с сайта --- */
app.post("/api/submit", rateLimiter, async (req, res) => {
  // Явная проверка Origin: чужой сайт не просто лишается CORS-заголовков,
  // а сразу получает отказ — так поведение прозрачнее и для тестов.
  const origin = req.headers.origin;
  if (origin && !ALLOWED_ORIGINS.includes(origin)) {
    return res.status(403).json({ success: false, error: "Домен не разрешён политикой CORS." });
  }

  const body = req.body || {};

  /* HONEYPOT: на сайте есть скрытое поле website_hp (человек его не видит
     и не заполняет, боты же автозаполняют). Если оно пришло непустым —
     это бот: молча возвращаем success, чтобы не выдавать фильтр, и в
     Telegram ничего не отправляем. */
  if (typeof body.website_hp === "string" && body.website_hp.trim() !== "") {
    console.log(`[${new Date().toISOString()}] honeypot сработал (IP ${req.ip}) — бот отфильтрован тихо`);
    return res.json({ success: true });
  }

  /* ВАЛИДАЦИЯ: типы, длины, белый список типов проекта */
  const validationError = validate(body);
  if (validationError) {
    return res.status(400).json({ success: false, error: validationError });
  }

  const name = body.name.trim();
  const contact = body.contact.trim();
  const type = body.type;
  const message = body.message.trim();
  const meta = (body.meta && typeof body.meta === "object") ? body.meta : null;

  /* ОТПРАВКА: любой сбой Telegram (сеть, таймаут, неверный токен) превращается
     в честный 502 с подсказкой запасного пути — сайт покажет это посетителю. */
  try {
    await sendToTelegram(name, contact, type, message, meta);
    console.log(`[${new Date().toISOString()}] ✅ заявка отправлена в Telegram: ${name} (${contact}), тип: ${type}`);
    return res.json({ success: true });
  } catch (err) {
    const isTimeout = err.name === "AbortError";
    console.error(`[${new Date().toISOString()}] ❌ ошибка Telegram API: ${isTimeout ? "таймаут 8с" : err.message}`);
    return res.status(502).json({
      success: false,
      error: isTimeout
        ? "Сервис уведомлений не ответил вовремя. Напишите напрямую в Telegram @angcorupt или на gorkaffg@gmail.com — заявка не потеряется."
        : "Не удалось отправить заявку через Telegram. Напишите напрямую в Telegram @angcorupt или на gorkaffg@gmail.com.",
    });
  }
});

/* ----------------------------------------------------------------------------
   6. ЕДИНЫЙ ОБРАБОТЧИК ОШИБОК (битый JSON, превышение лимита тела, прочее)
   ---------------------------------------------------------------------------- */
app.use((err, req, res, next) => {
  if (err.type === "entity.too.large") {
    return res.status(413).json({ success: false, error: "Заявка слишком большая (лимит 16 КБ)." });
  }
  if (err.type === "entity.parse.failed" || err instanceof SyntaxError) {
    return res.status(400).json({ success: false, error: "Тело запроса — некорректный JSON." });
  }
  console.error("[error] непредвиденная ошибка:", err);
  return res.status(500).json({ success: false, error: "Внутренняя ошибка сервера." });
});

/* ----------------------------------------------------------------------------
   7. СТАРТ
   ---------------------------------------------------------------------------- */
app.listen(PORT, () => {
  console.log("✅ Бот заявок запущен: http://localhost:" + PORT);
  console.log("   Форма сайта шлёт заявки сюда (js/config.js → formEndpoint).");
  console.log("   Разрешённые домены: " + (ALLOWED_ORIGINS.join(", ") || "— не заданы —"));
  console.log("   Лимит: " + MAX_REQ_PER_WINDOW + " заявок в " + (WINDOW_MS / 1000) + "с с одного IP");
  console.log("   Telegram: chat_id=" + (CHAT_ID || "—") + ", токен " +
    (BOT_TOKEN && !BOT_TOKEN.includes("ВСТАВЬТЕ") ? "задан ✓" : "НЕ задан (впишите в bot/.env)"));
});
