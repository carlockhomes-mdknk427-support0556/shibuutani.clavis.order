// ══════════════════════════════════════════════════
//  web-order-worker.js への追記内容
//  追記場所: POST処理ブロック（line 459）の直前
//
//  追記後の wrangler.toml [vars] に以下を追加:
//    GAS_PROPERTY_URL = "https://script.google.com/.../exec"
// ══════════════════════════════════════════════════

// ── 物件マスター照合 (/property GET) ────────────────
if (request.method === 'GET' && url.pathname === '/property') {
  const pass = url.searchParams.get('pass')
  const key  = url.searchParams.get('key')
  if (key !== env.ORDER_API_KEY) {
    return new Response(
      JSON.stringify({ status: 'error', message: '認証エラー' }),
      { status: 401, headers: { ...cors, 'Content-Type': 'application/json' } }
    )
  }
  if (!pass) {
    return new Response(
      JSON.stringify({ status: 'error', message: 'PASSコードが必要です' }),
      { status: 400, headers: { ...cors, 'Content-Type': 'application/json' } }
    )
  }
  try {
    const gasRes = await fetch(
      `${env.GAS_PROPERTY_URL}?pass=${encodeURIComponent(pass)}`
    )
    const text = await gasRes.text()
    return new Response(text, {
      headers: { ...cors, 'Content-Type': 'application/json' },
    })
  } catch (e) {
    return errorResponse(cors, e)
  }
}
