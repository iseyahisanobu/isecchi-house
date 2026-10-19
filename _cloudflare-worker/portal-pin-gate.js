// いせっちハウス スタッフポータル（/portal/ 以下全体）用
// 4桁パスワードゲート ＋ お知らせ掲示板APIの Cloudflare Worker
//
// このファイルはこのリポジトリの静的サイト（GitHub Pages）には公開されません
// （ファイル名が "_" で始まるフォルダは Jekyll によって自動的に除外されるため）。
// Cloudflare のWorkerエディタにこのコードをそのまま貼り付けて使用します。
//
// 【事前に Cloudflare 側で用意するもの】
//   1. KV Namespace（例: PORTAL_KV）を作成し、このWorkerにバインドする
//      - キー "pin"      … 全スタッフ用の閲覧パスワード（4桁）
//      - キー "post_pin" … お知らせの投稿・削除ができる一部スタッフ用のパスワード（4桁、"pin"とは別の値にする）
//        （どちらもコードには書かず、KVの値としてのみ保存する。
//          変更したいときは、該当キーの値をCloudflareダッシュボードで書き換えるだけでよい）
//      - キー "announcements" は自動的に使われるため、事前に用意する必要はありません
//      - キー "page_riyousha_joho" / "page_security" … 個人情報・パスワードを含むため
//        GitHubリポジトリ（Public）には置かず、この2ページの中身（HTML全文）をKVに直接保存する。
//        該当ページへのアクセスはオリジン（GitHub Pages）へ転送せず、ここから配信する。
//   2. Secret（環境変数） SESSION_SECRET を設定する（ログイン状態を保つ署名鍵。
//      ランダムな長い文字列を1つ決めて設定すればよい。人に教える必要はない）
//   3. このWorkerを、ポータル全体をカバーするRoute（例: isecchi.com/portal/*）に割り当てる
//      （/portal/ 以下のどのページに直接アクセスしても、まずこの閲覧PIN画面が出るようになる）
//   4. （レシート提出機能）Secret RECEIPT_GAS_URL と RECEIPT_TOKEN を設定する
//      - RECEIPT_GAS_URL … Google Apps Script（_google-apps-script/receipt-upload.gs）のウェブアプリURL
//      - RECEIPT_TOKEN   … 同スクリプトの setup 実行時に表示される合言葉
//      （どちらもブラウザには一切送られない。スタッフのスマホからは /portal/api/receipt しか見えない）
//
// 【動作】
//   - 未認証の場合：4桁の閲覧パスワード入力フォームを表示
//   - 正しいPINを入力：以後12時間、ブラウザに保存されたCookieで再入力不要
//   - 誤ったPINを10回連続で入力：そのアクセス元を30分間ロック
//   - 正しく認証された場合のみ、実際のページ内容（GitHub Pages側の本文）を返す
//     （認証前は本文が一切ブラウザに送信されない）
//   - 閲覧認証済みのアクセスのうち、/portal/api/announcements 宛のリクエストは
//     オリジンへ転送せず、この Worker が KV を使って直接お知らせの取得・投稿・削除を処理する
//   - お知らせの投稿・削除には、閲覧パスワードとは別の「投稿用パスワード」の確認が必要
//     （/portal/api/post-auth に4桁を送ると、以後12時間はCookieで再入力不要）
//   - 閲覧認証済みの /portal/api/receipt 宛のPOST（レシート写真）は、合言葉を付けて
//     Google Apps Script に中継し、Googleドライブに保存させる

const COOKIE_NAME = "portal_auth";
const POST_COOKIE_NAME = "portal_post_auth";
const VIEW_PIN_KEY = "pin";
const POST_PIN_KEY = "post_pin";
const ANNOUNCEMENTS_KEY = "announcements";
const ANNOUNCEMENTS_PATH = "/portal/api/announcements";
const POST_AUTH_PATH = "/portal/api/post-auth";
const RECEIPT_PATH = "/portal/api/receipt";
const RECEIPT_MAX_BODY_BYTES = 4 * 1024 * 1024; // 画像はスマホ側で約1.5MB以下に縮めてから送られる

// 個人情報・パスワードを含むため、GitHub（Public）には置かずKVから直接配信するページ
const KV_PAGES = {
  "/portal/riyousha-joho.html": "page_riyousha_joho",
  "/portal/security.html": "page_security",
  "/portal/receipt.html": "page_receipt", // レシート提出（スタッフ氏名を含むため）
};

const MAX_ATTEMPTS = 10;
const LOCK_DURATION_SECONDS = 30 * 60;      // ロック時間：30分
const ATTEMPT_WINDOW_SECONDS = 30 * 60;     // 失敗回数を数える期間：30分
const SESSION_DURATION_SECONDS = 60 * 60 * 12; // ログイン維持時間：12時間

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const cookie = request.headers.get("Cookie") || "";
    const sessionToken = getCookieValue(cookie, COOKIE_NAME);
    const viewAuthed = sessionToken && (await isValidSession(sessionToken, env, "view"));
    const isApiPath = url.pathname === ANNOUNCEMENTS_PATH || url.pathname === POST_AUTH_PATH || url.pathname === RECEIPT_PATH;

    if (!viewAuthed) {
      if (isApiPath) {
        return jsonResponse({ error: "view_auth_required" }, 401);
      }

      const lockKey = `lock:${ip}`;
      const isLocked = await env.PORTAL_KV.get(lockKey);
      if (isLocked) {
        return renderPage(lockedBody(), 429);
      }

      if (request.method === "POST") {
        const form = await request.formData();
        const inputPin = (form.get("pin") || "").toString().trim();
        const validPin = await env.PORTAL_KV.get(VIEW_PIN_KEY);

        if (validPin && inputPin === validPin) {
          await env.PORTAL_KV.delete(`attempts:${ip}`);
          const token = await createSessionToken(env, "view");
          // 同じURLへ303で移動し直す。ここでオリジンを直接取りに行くと、KV配信ページ（GitHubに無いページ）が404になる
          return new Response(null, {
            status: 303,
            headers: {
              Location: request.url,
              "Cache-Control": "no-store",
              "Set-Cookie": `${COOKIE_NAME}=${token}; Path=/; Max-Age=${SESSION_DURATION_SECONDS}; HttpOnly; Secure; SameSite=Lax`,
            },
          });
        }

        const attemptsKey = `attempts:${ip}`;
        const attempts = (parseInt((await env.PORTAL_KV.get(attemptsKey)) || "0", 10)) + 1;

        if (attempts >= MAX_ATTEMPTS) {
          await env.PORTAL_KV.put(lockKey, "1", { expirationTtl: LOCK_DURATION_SECONDS });
          await env.PORTAL_KV.delete(attemptsKey);
          return renderPage(lockedBody(), 429);
        }

        await env.PORTAL_KV.put(attemptsKey, String(attempts), { expirationTtl: ATTEMPT_WINDOW_SECONDS });
        return renderPage(pinFormBody(true), 401);
      }

      // 200で返す：LINE等のリンクプレビュー用クローラーが401のページのサムネ情報を読まないことがあるため
      return renderPage(pinFormBody(false), 200);
    }

    // ここから下は閲覧PIN認証済み
    // ログイン済みでPIN送信が再度届いた場合（二重送信・リロード）は405にせず、ページ表示へ戻す
    if (request.method === "POST" && !isApiPath) {
      return new Response(null, { status: 303, headers: { Location: request.url, "Cache-Control": "no-store" } });
    }
    if (url.pathname === ANNOUNCEMENTS_PATH) {
      return handleAnnouncementsApi(request, env, ip);
    }
    if (url.pathname === POST_AUTH_PATH) {
      return handlePostAuthApi(request, env, ip);
    }
    if (url.pathname === RECEIPT_PATH) {
      return handleReceiptApi(request, env);
    }
    if (url.pathname in KV_PAGES) {
      return handleKvPage(env, KV_PAGES[url.pathname]);
    }
    return fetch(request); // 通常ページはそのままオリジンへ
  },
};

// ---- KVから直接配信するページ（個人情報・パスワードを含むもの） ----

async function handleKvPage(env, kvKey) {
  const html = await env.PORTAL_KV.get(kvKey);
  if (!html) {
    return new Response("このページは準備中です。", {
      status: 200,
      headers: { "Content-Type": "text/html; charset=UTF-8" },
    });
  }
  return new Response(html, {
    status: 200,
    headers: { "Content-Type": "text/html; charset=UTF-8" },
  });
}

// ---- お知らせAPI ----

async function handleAnnouncementsApi(request, env, ip) {
  const url = new URL(request.url);

  if (request.method === "GET") {
    const list = await getAnnouncements(env);
    const today = todayString();
    const visible = list.filter((a) => a.category !== "daily" || a.createdAt === today);
    return jsonResponse(visible, 200);
  }

  // 投稿・削除は投稿用パスワードの認証が必要
  const cookie = request.headers.get("Cookie") || "";
  const postToken = getCookieValue(cookie, POST_COOKIE_NAME);
  const postAuthed = postToken && (await isValidSession(postToken, env, "post"));
  if (!postAuthed) {
    return jsonResponse({ error: "post_auth_required" }, 401);
  }

  if (request.method === "POST") {
    let body;
    try {
      body = await request.json();
    } catch (e) {
      return jsonResponse({ error: "invalid_body" }, 400);
    }
    const category = body.category === "daily" ? "daily" : "general";
    const title = (body.title || "").toString().trim().slice(0, 60);
    const text = (body.body || "").toString().trim().slice(0, 500);
    if (!title || !text) {
      return jsonResponse({ error: "invalid_body" }, 400);
    }

    const list = await getAnnouncements(env);
    const newItem = {
      id: crypto.randomUUID(),
      category,
      title,
      body: text,
      createdAt: todayString(),
    };
    list.unshift(newItem);
    await env.PORTAL_KV.put(ANNOUNCEMENTS_KEY, JSON.stringify(list));
    return jsonResponse(newItem, 201);
  }

  if (request.method === "DELETE") {
    const id = url.searchParams.get("id");
    if (!id) return jsonResponse({ error: "missing_id" }, 400);
    const list = await getAnnouncements(env);
    const filtered = list.filter((a) => a.id !== id);
    await env.PORTAL_KV.put(ANNOUNCEMENTS_KEY, JSON.stringify(filtered));
    return jsonResponse({ ok: true }, 200);
  }

  return jsonResponse({ error: "method_not_allowed" }, 405);
}

async function getAnnouncements(env) {
  const raw = await env.PORTAL_KV.get(ANNOUNCEMENTS_KEY);
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (e) {
    return [];
  }
}

function todayString() {
  // 日本国内の施設利用のため、JST基準で「今日」を判定する
  const jst = new Date(Date.now() + 9 * 60 * 60 * 1000);
  return jst.toISOString().slice(0, 10);
}

function jsonResponse(data, status) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=UTF-8" },
  });
}

// ---- レシート提出API（Google Apps Script への中継） ----

async function handleReceiptApi(request, env) {
  if (request.method !== "POST") {
    return jsonResponse({ error: "method_not_allowed" }, 405);
  }
  if (!env.RECEIPT_GAS_URL || !env.RECEIPT_TOKEN) {
    return jsonResponse({ ok: false, error: "not_configured" }, 503);
  }
  const length = parseInt(request.headers.get("Content-Length") || "0", 10);
  if (length > RECEIPT_MAX_BODY_BYTES) {
    return jsonResponse({ ok: false, error: "invalid_image" }, 413);
  }

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonResponse({ ok: false, error: "invalid_body" }, 400);
  }
  const payload = {
    token: env.RECEIPT_TOKEN,
    name: (body.name || "").toString(),
    amount: Number(body.amount),
    image: (body.image || "").toString(),
    quality: (body.quality || "").toString().slice(0, 50),
    note: (body.note || "").toString().slice(0, 100),
    confirmed: body.confirmed === true, // 金額が合わないと言われたあと、本人が「合っている」と押した
  };
  if (payload.image.length > RECEIPT_MAX_BODY_BYTES) {
    return jsonResponse({ ok: false, error: "invalid_image" }, 413);
  }

  try {
    // Apps Script のウェブアプリは処理後に別URLへリダイレクトして結果を返すため、リダイレクトを追う
    const res = await fetch(env.RECEIPT_GAS_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      redirect: "follow",
    });
    const text = await res.text();
    let result;
    try {
      result = JSON.parse(text);
    } catch (e) {
      return jsonResponse({ ok: false, error: "upstream_error" }, 502);
    }
    if (result.error === "amount_mismatch") {
      // レシートの読み取り結果と入力金額が合わない（まだ保存していない）。スタッフの画面で確認してもらう
      return jsonResponse({ ok: false, error: "amount_mismatch", ocrTotal: result.ocrTotal || null }, 409);
    }
    if (!result.ok) {
      return jsonResponse({ ok: false, error: result.error || "upstream_error" }, 502);
    }
    return jsonResponse({ ok: true, fileName: result.fileName, amount: result.amount, received: result.received }, 200);
  } catch (e) {
    return jsonResponse({ ok: false, error: "upstream_error" }, 502);
  }
}

// ---- 投稿用パスワード認証 ----

async function handlePostAuthApi(request, env, ip) {
  if (request.method !== "POST") {
    return jsonResponse({ error: "method_not_allowed" }, 405);
  }

  const lockKey = `post_lock:${ip}`;
  const isLocked = await env.PORTAL_KV.get(lockKey);
  if (isLocked) {
    return jsonResponse({ error: "locked" }, 429);
  }

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonResponse({ error: "invalid_body" }, 400);
  }
  const inputPin = (body.pin || "").toString().trim();
  const validPin = await env.PORTAL_KV.get(POST_PIN_KEY);

  if (validPin && inputPin === validPin) {
    await env.PORTAL_KV.delete(`post_attempts:${ip}`);
    const token = await createSessionToken(env, "post");
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: {
        "Content-Type": "application/json; charset=UTF-8",
        "Set-Cookie": `${POST_COOKIE_NAME}=${token}; Path=/; Max-Age=${SESSION_DURATION_SECONDS}; HttpOnly; Secure; SameSite=Lax`,
      },
    });
  }

  const attemptsKey = `post_attempts:${ip}`;
  const attempts = (parseInt((await env.PORTAL_KV.get(attemptsKey)) || "0", 10)) + 1;
  if (attempts >= MAX_ATTEMPTS) {
    await env.PORTAL_KV.put(lockKey, "1", { expirationTtl: LOCK_DURATION_SECONDS });
    await env.PORTAL_KV.delete(attemptsKey);
    return jsonResponse({ error: "locked" }, 429);
  }
  await env.PORTAL_KV.put(attemptsKey, String(attempts), { expirationTtl: ATTEMPT_WINDOW_SECONDS });
  return jsonResponse({ error: "invalid_pin" }, 401);
}

// ---- 共通ユーティリティ ----

function getCookieValue(cookieHeader, name) {
  const match = cookieHeader.match(new RegExp(`${name}=([^;]+)`));
  return match ? match[1] : null;
}

async function hmac(env, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.SESSION_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function createSessionToken(env, purpose) {
  const expires = Date.now() + SESSION_DURATION_SECONDS * 1000;
  const payload = `${purpose}:${expires}`;
  const sig = await hmac(env, payload);
  return `${payload}.${sig}`;
}

async function isValidSession(token, env, purpose) {
  const dotIndex = token.lastIndexOf(".");
  if (dotIndex === -1) return false;
  const payload = token.slice(0, dotIndex);
  const sig = token.slice(dotIndex + 1);
  if (!payload || !sig) return false;
  const expected = await hmac(env, payload);
  if (expected !== sig) return false;
  const [tokenPurpose, expiresStr] = payload.split(":");
  if (tokenPurpose !== purpose) return false;
  return Date.now() < parseInt(expiresStr, 10);
}

// ---- 閲覧PIN画面のHTML ----

function renderPage(body, status) {
  return new Response(
    `<!DOCTYPE html>
<html lang="ja"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>パスワード確認｜いせっちハウス</title>
<meta property="og:type" content="website">
<meta property="og:site_name" content="いせっちハウス">
<meta property="og:title" content="いせっちハウス スタッフ専用ポータル">
<meta property="og:description" content="スタッフ専用ページです。開くにはパスワードが必要です。">
<meta property="og:image" content="https://isecchi.com/ogp/portal-ogp-v2.jpg">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<style>
  body { font-family: sans-serif; background: #FAFDF3; display: flex; align-items: center;
         justify-content: center; min-height: 100vh; margin: 0; }
  .box { background: #fff; border-radius: 16px; box-shadow: 0 2px 12px rgba(0,0,0,.1);
         padding: 32px; max-width: 320px; width: 90%; text-align: center; }
  input { font-size: 28px; letter-spacing: 12px; text-align: center; width: 100%;
          padding: 12px; margin: 16px 0; border: 2px solid #DBF2B8; border-radius: 8px;
          box-sizing: border-box; }
  button { font-size: 18px; font-weight: bold; background: #6DBE45; color: #fff; border: none;
           border-radius: 8px; padding: 12px 24px; width: 100%; cursor: pointer; }
  .err { color: #dc2626; font-size: 14px; margin-top: -8px; margin-bottom: 8px; }
</style></head>
<body>${body}</body></html>`,
    { status, headers: { "Content-Type": "text/html; charset=UTF-8" } }
  );
}

function pinFormBody(showError) {
  return `<div class="box">
    <h1 style="font-size:18px;">スタッフ専用ページ</h1>
    <p style="font-size:14px;color:#475569;">4桁のパスワードを入力してください</p>
    ${showError ? '<p class="err">パスワードが違います</p>' : ""}
    <form method="POST">
      <input type="tel" name="pin" maxlength="4" pattern="[0-9]{4}" inputmode="numeric" autofocus required>
      <button type="submit">開く</button>
    </form>
  </div>`;
}

function lockedBody() {
  return `<div class="box">
    <h1 style="font-size:18px;">一時的にロックされています</h1>
    <p style="font-size:14px;color:#475569;">
      入力回数が上限に達しました。30分ほど時間をおいて、再度お試しください。
    </p>
  </div>`;
}
