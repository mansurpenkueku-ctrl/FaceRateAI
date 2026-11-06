import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const store = getStore("facerate-users");
const COOKIE = "fr_session";

const secret = () => process.env.SESSION_SECRET || "";

function sign(value) {
  return crypto.createHmac("sha256", secret())
    .update(value)
    .digest("base64url");
}

function token(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return data + "." + sign(data);
}

function getSession(event) {
  const cookies = event.headers?.cookie || "";
  const raw = cookies.split(";")
    .map(x => x.trim())
    .find(x => x.startsWith(COOKIE + "="))
    ?.slice(COOKIE.length + 1);

  if (!raw || !secret()) return null;

  const [data, signature] = raw.split(".");
  if (!data || !signature) return null;

  const expected = sign(data);

  if (
    signature.length !== expected.length ||
    !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))
  ) return null;

  try {
    const session = JSON.parse(
      Buffer.from(data, "base64url").toString()
    );

    if (session.exp < Date.now()) return null;
    return session;
  } catch {
    return null;
  }
}

function reply(statusCode, data, headers = {}) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      ...headers
    },
    body: JSON.stringify(data)
  };
}

function setCookie(payload) {
  const value = token({
    ...payload,
    exp: Date.now() + 7 * 86400000
  });

  return {
    "Set-Cookie": `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`
  };
}

async function getUsers() {
  return await store.get("users", { type: "json" }) || [];
}

async function saveUsers(users) {
  await store.setJSON("users", users);
}

function entitlement(user) {
  const e = user.entitlement || { plan: "free", expiresAt: null };

  if (
    e.expiresAt &&
    e.expiresAt !== "lifetime" &&
    Date.parse(e.expiresAt) <= Date.now()
  ) {
    return { plan: "free", expiresAt: null };
  }

  return e;
}

function safeUser(user) {
  return {
    id: user.id,
    email: user.email,
    createdAt: user.createdAt,
    entitlement: entitlement(user)
  };
}

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString("hex");
}

function verifyPassword(password, user) {
  const a = Buffer.from(hashPassword(password, user.salt), "hex");
  const b = Buffer.from(user.passwordHash, "hex");

  return a.length === b.length &&
    crypto.timingSafeEqual(a, b);
}

export default async function handler(event) {
  if (event.httpMethod === "OPTIONS") {
    return reply(204, {});
  }

  const path = (event.path || "").split("/").pop();

  let body = {};

  try {
    body = event.body ? JSON.parse(event.body) : {};
  } catch {
    return reply(400, { error: "Некорректный JSON" });
  }

  try {
    if (path === "register" || path === "login") {
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");

      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return reply(400, { error: "Некорректный email" });
      }

      let users = await getUsers();
      let user = users.find(u => u.email === email);

      if (path === "register") {
        if (password.length < 8) {
          return reply(400, { error: "Минимум 8 символов в пароле" });
        }

        if (user) {
          return reply(409, { error: "Аккаунт уже существует" });
        }

        const salt = crypto.randomBytes(16).toString("hex");

        user = {
          id: crypto.randomUUID(),
          email,
          salt,
          passwordHash: hashPassword(password, salt),
          createdAt: new Date().toISOString(),
          entitlement: {
            plan: "free",
            expiresAt: null
          }
        };

        users.push(user);
        await saveUsers(users);

      } else if (!user || !verifyPassword(password, user)) {
        return reply(401, { error: "Неверный email или пароль" });
      }

      return reply(
        200,
        { user: safeUser(user) },
        setCookie({ uid: user.id, role: "user" })
      );
    }

    if (path === "admin-login") {
      if (
        !process.env.ADMIN_EMAIL ||
        !process.env.ADMIN_PASSWORD ||
        !secret()
      ) {
        return reply(503, {
          error: "Не настроены переменные администратора"
        });
      }

      const correct =
        String(body.email || "").toLowerCase() ===
          process.env.ADMIN_EMAIL.toLowerCase() &&
        String(body.password || "") ===
          process.env.ADMIN_PASSWORD;

      if (!correct) {
        return reply(401, { error: "Неверные данные" });
      }

      return reply(200, { ok: true }, setCookie({ role: "admin" }));
    }

    if (path === "logout") {
      return reply(200, { ok: true }, {
        "Set-Cookie": `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
      });
    }

    const session = getSession(event);

    if (path === "me") {
      if (!session || session.role !== "user") {
        return reply(401, { error: "Не авторизован" });
      }

      const user = (await getUsers()).find(u => u.id === session.uid);

      if (!user) return reply(401, { error: "Пользователь не найден" });

      return reply(200, { user: safeUser(user) });
    }

    if (["users", "grant", "revoke"].includes(path)) {
      if (!session || session.role !== "admin") {
        return reply(403, { error: "Нет доступа" });
      }

      const users = await getUsers();

      if (path === "users") {
        const q = String(
          event.queryStringParameters?.q || ""
        ).toLowerCase();

        return reply(200, {
          users: users
            .filter(u => u.email.includes(q))
            .map(safeUser)
        });
      }

      const email = String(body.email || "").trim().toLowerCase();
      const user = users.find(u => u.email === email);

      if (!user) {
        return reply(404, { error: "Пользователь не найден" });
      }

      if (path === "revoke") {
        user.entitlement = {
          plan: "free",
          expiresAt: null
        };
      } else {
        const plan = ["premium", "full"].includes(body.plan)
          ? body.plan
          : null;

        const days = String(body.days || "30");

        if (!plan || !["30", "90", "365", "lifetime"].includes(days)) {
          return reply(400, { error: "Некорректный тариф или срок" });
        }

        user.entitlement = {
          plan,
          expiresAt: days === "lifetime"
            ? "lifetime"
            : new Date(
                Date.now() + Number(days) * 86400000
              ).toISOString(),
          grantedAt: new Date().toISOString()
        };
      }

      await saveUsers(users);

      return reply(200, { user: safeUser(user) });
    }

    return reply(404, { error: "Маршрут не найден" });

  } catch (error) {
    console.error(error);

    return reply(500, {
      error: "Внутренняя ошибка сервера"
    });
  }
    }
