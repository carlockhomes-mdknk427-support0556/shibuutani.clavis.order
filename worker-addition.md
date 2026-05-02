// ══════════════════════════════════════════════════
//  web-order-worker.js への /property ハンドラ追加版（実装済み）
//
//  このファイルは documentation 用。実装は
//  /Users/.../追加注文WEB/注文サイト/web-order-worker.js 内の `/property` 分岐に統合済み。
//  ここでは Clavis 側の要件を満たすための最終形を示す。
//
//  セキュリティ機能（key-order-app 同水準）:
//    - Origin/Referer 完全一致検証（ALLOWED_ORIGINS）
//    - Rate Limiting（IP 単位、デフォルト 30 qpm）
//    - Honeypot 連動ブロック（30 分間・2 回/分で厳格化）
//    - HMAC 署名生成（WORKER_HMAC_KEY）で GAS 側の HMAC 検証に対応
//    - GAS fetch タイムアウト（10 秒 AbortController）
//    - 不正 JSON → 400 Bad Request
//    - logWorkerError で GAS 監査ログへエラー送信
//    - ハニーポット基盤（/admin, /.env, /wp-admin 等）
//
//  追記後の wrangler.toml [vars] に以下を追加:
//    GAS_PROPERTY_URL = "https://script.google.com/.../exec"
//    WORKER_HMAC_KEY  (secret): GAS と同値
//    WORKER_LOG_KEY   (secret): GAS と同値
//    ORDER_API_KEY    (secret): GAS と同値
// ══════════════════════════════════════════════════

// ── 物件マスター照合 (/property GET) — 統合版（参考実装） ────────────────
// 前提: getCorsHeaders / ALLOWED_ORIGINS / fetchGAS / isAbortError /
//       gatewayTimeoutResponse / errorResponse / logWorkerError /
//       generateWorkerHmac / checkRateLimit は worker.js 側で定義済み
//
// if (request.method === 'GET' && url.pathname === '/property') {
//   // 1) Origin / Referer 検証
//   const origin   = request.headers.get('Origin') || '';
//   const referer  = request.headers.get('Referer') || '';
//   const originOk = ALLOWED_ORIGINS.includes(origin);
//   let refererOk  = false;
//   if (referer) {
//     try { refererOk = ALLOWED_ORIGINS.includes(new URL(referer).origin); } catch(_) {}
//   }
//   if (!originOk && !refererOk) {
//     logWorkerError(env, ctx, request, url, 'csrf_block', 403, 'origin=' + origin);
//     return new Response(
//       JSON.stringify({ status: 'error', message: 'Forbidden' }),
//       { status: 403, headers: { ...cors, 'Content-Type': 'application/json' } }
//     );
//   }
//
//   // 2) PASS コード検証（形式チェックのみ：4〜12 桁の英数字）
//   const pass = url.searchParams.get('pass') || '';
//   if (!pass) {
//     return new Response(
//       JSON.stringify({ status: 'error', message: 'PASSコードが必要です' }),
//       { status: 400, headers: { ...cors, 'Content-Type': 'application/json' } }
//     );
//   }
//   if (!/^[a-zA-Z0-9]{4,12}$/.test(pass)) {
//     return new Response(
//       JSON.stringify({ status: 'error', message: 'PASSコードの形式が不正です' }),
//       { status: 400, headers: { ...cors, 'Content-Type': 'application/json' } }
//     );
//   }
//
//   // 3) Rate Limiting（IP 単位）— デフォルト 30 qpm
//   const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
//   if (!checkRateLimit(clientIP, '/property')) {
//     logWorkerError(env, ctx, request, url, 'rate_limit', 429, 'path=/property');
//     return new Response(
//       JSON.stringify({ status: 'error', message: 'リクエストが多すぎます' }),
//       { status: 429, headers: { ...cors, 'Content-Type': 'application/json' } }
//     );
//   }
//
//   // 4) HMAC 署名生成（GAS 側で WORKER_HMAC_KEY で検証）
//   const timestamp = Date.now();
//   const hmacSig   = await generateWorkerHmac(env, 'get_property', pass, timestamp);
//   const qs        = new URLSearchParams({ pass });
//   if (env.ORDER_API_KEY) qs.set('apiKey', env.ORDER_API_KEY);
//   if (hmacSig) { qs.set('ts', String(timestamp)); qs.set('hmac', hmacSig); }
//
//   // 5) GAS へ転送（タイムアウト付き）
//   try {
//     const gasRes = await fetchGAS(`${env.GAS_PROPERTY_URL}?${qs.toString()}`);
//     const text   = await gasRes.text();
//     return new Response(text, {
//       headers: { ...cors, 'Content-Type': 'application/json' },
//     });
//   } catch (e) {
//     if (isAbortError(e)) {
//       logWorkerError(env, ctx, request, url, 'gas_timeout', 504, 'path=/property');
//       return gatewayTimeoutResponse(cors);
//     }
//     return errorResponse(cors, e, { env, ctx, request, url });
//   }
// }
