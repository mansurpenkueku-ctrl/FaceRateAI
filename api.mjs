import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const store = getStore("facerate-users");
const COOKIE = "fr_session";
const secret = () => process.env.SESSION_SECRET || "";
const b64 = s => Buffer.from(s).toString("base64url");
const sign = s => crypto.createHmac("sha256", secret()).update(s).digest("base64url");

function makeToken(payload) {
  const p = b64(JSON.stringify(payload));
  return p + "." + sign(p);
}

function readToken(event) {
  const h = event.headers?.cookie || event.headers?.Cookie || "";
  const raw = h.split(";").map(x => x.trim())
    .find(x => x.startsWith(COOKIE + "="))
    ?.slice(COOKIE.length + 1);

  if (!raw) return null;
  const [p, s] = raw.split(".");
  if (!p || !s || !secret()) return null;

  const expected = sign(p);
  if (s.length !== expected.length ||
      !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(expected))) return null;

  try {
    const v = JSON.parse(Buffer.from(p, "base64url").toString());
    if (v.exp < Date.now()) return null;
    return v;
  } catch {
    return null;
  }
}

function cookie(value, maxAge = 604800) {
  return `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

function response(status, body, headers = {}) {
  return {
    statusCode: status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...headers
    },
    body: JSON.stringify(body)
  };
}

async function allUsers() {
  return await store.get("users", { type: "json" }) || [];
}

async function saveUsers(users) {
  await store.setJSON("users", users);
}

function publicUser(u) {
  return {
    id: u.id,
    email: u.email,
    createdAt: u.createdAt,
    entitlement: activeEntitlement(u)
  };
}

function activeEntitlement(u) {
  const e = u.entitlement || { plan: "free", expiresAt: null };
  if (e.expiresAt && e.expiresAt !== "lifetime" &&
      Date.parse(e.expiresAt) <= Date.now()) {
    return { plan: "free", expiresAt: null };
  }
  return e;
}

function hashPassword(pass, salt) {
  return crypto.scryptSync(pass, salt, 64).toString("hex");
}

function verifyPassword(pass, u) {
  const got = Buffer.from(hashPassword(pass, u.salt), "hex");
  const want = Buffer.from(u.passwordHash, "hex");
  return got.length === want.length &&
    crypto.timingSafeEqual(got, want);
}

function issue(payload) {
  return {
    "Set-Cookie": cookie(
      makeToken({
        ...payload,
        exp: Date.now() + 7 * 86400000
      })
    )
  };
}

export default async function handler(event) {
  if (event.httpMethod === "OPTIONS") return response(204, {});

  const path = event.path.split("/").pop();
  let body = {};

  try {
    body = event.body ? JSON.parse(event.body) : {};
  } catch {
    return response(400, { error: "Некорректный JSON" });
  }

  try {
    if (path === "register" || path === "login") {
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");

      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return response(400, { error: "Введите корректный email" });
      }

      let users = await allUsers();
      let u = users.find(x => x.email === email);

      if (path === "register") {
        if (password.length < 8) {
          return response(400, { error: "Пароль должен быть не короче 8 символов" });
        }
        if (u) return response(409, { error: "Этот email уже зарегистрирован" });

        const salt = crypto.randomBytes(16).toString("hex");
        u = {
          id: crypto.randomUUID(),
          email,
          salt,
          passwordHash: hashPassword(password, salt),
          createdAt: new Date().toISOString(),
          entitlement: { plan: "free", expiresAt: null }
        };

        users.push(u);
        await saveUsers(users);
      } else if (!u || !verifyPassword(password, u)) {
        return response(401, { error: "Неверный email или пароль" });
      }

      return response(200, { user: publicUser(u) }, issue({ uid: u.id, role: "user" }));
    }

    if (path === "admin-login") {
      if (!process.env.ADMIN_EMAIL ||
          !process.env.ADMIN_PASSWORD ||
          !secret()) {
        return response(503, {
          error: "Добавь ADMIN_EMAIL, ADMIN_PASSWORD и SESSION_SECRET в Netlify environment variables"
        });
      }

      const ok =
        String(body.email || "").toLowerCase() === process.env.ADMIN_EMAIL.toLowerCase() &&
        String(body.password || "") === process.env.ADMIN_PASSWORD;

      if (!ok) return response(401, { error: "Неверные данные администратора" });

      return response(200, { ok: true }, issue({ role: "admin" }));
    }

    if (path === "logout") {
      return response(200, { ok: true }, {
        "Set-Cookie": cookie("", 0)
      });
    }

    const session = readToken(event);

    if (path === "me") {
      if (!session || session.role !== "user") {
        return response(401, { error: "Не авторизован" });
      }

      const u = (await allUsers()).find(x => x.id === session.uid);
      if (!u) return response(401, { error: "Аккаунт не найден" });

      return response(200, { user: publicUser(u) });
    }

    if (["users", "grant", "revoke"].includes(path)) {
      if (!session || session.role !== "admin") {
        return response(403, { error: "Только администратор" });
      }

      let users = await allUsers();

      if (path === "users") {
        const q = String(event.queryStringParameters?.q || "").toLowerCase();
        return response(200, {
          users: users.filter(u => u.email.includes(q)).map(publicUser)
        });
      }

      const email = String(body.email || "").trim().toLowerCase();
      const u = users.find(x => x.email === email);

      if (!u) return response(404, { error: "Пользователь не найден" });

      if (path === "revoke") {
        u.entitlement = { plan: "free", expiresAt: null };
      } else {
        const plan = ["premium", "full"].includes(body.plan) ? body.plan : null;
        const days = String(body.days || "30");

        if (!plan || !["30", "90", "365", "lifetime"].includes(days)) {
          return response(400, { error: "Некорректный тариф или срок" });
        }

        u.entitlement = {
          plan,
          expiresAt: days === "lifetime"
            ? "lifetime"
            : new Date(Date.now() + Number(days) * 86400000).toISOString(),
          grantedAt: new Date().toISOString()
        };
      }

      await saveUsers(users);
      return response(200, { user: publicUser(u) });
    }

    return response(404, { error: "Маршрут не найден" });
  } catch (e) {
    console.error(e);
    return response(500, { error: "Внутренняя ошибка сервера" });
  }
}
