const WORKER_URL = 'https://web-order.clh-0556-clh.workers.dev'
// No.4是正(2026-04-14): APIキー直書き削除 → Worker側でOrigin検証に変更
// [v3.17 H-11 (2026-04-27 JST)] CSRF + Turnstile 対応
//   web-order Worker が add_order に CSRF + Turnstile を必須化したため、
//   Clavis 側でも /csrf-token 取得 + Turnstile invisible widget で token を同梱送信。

/**
 * Worker から CSRF token を取得（5 分有効、IP バインド）
 */
export async function fetchCsrfToken() {
  const res = await fetch(`${WORKER_URL}/csrf-token`, {
    method: 'GET',
    credentials: 'omit',
  })
  if (!res.ok) throw new Error('セキュリティトークン取得失敗 (' + res.status + ')')
  const data = await res.json()
  if (!data.token) throw new Error('セキュリティトークン未発行')
  return data.token
}

/**
 * PASSコードから物件情報を取得
 */
export async function fetchProperty(passCode) {
  const res = await fetch(
    `${WORKER_URL}/property?pass=${encodeURIComponent(passCode)}`
  )
  if (!res.ok) throw new Error('物件情報の取得に失敗しました')
  const data = await res.json()
  if (data.status !== 'ok') throw new Error(data.message || '物件が見つかりません')
  return data.property
}

/**
 * 注文をGAS経由で送信
 * @param {Object} payload  注文データ
 * @param {string} turnstileToken  Cloudflare Turnstile widget が発行した token
 */
export async function submitOrder(payload, turnstileToken) {
  // [v3.17 H-11] CSRF token を取得
  const csrfToken = await fetchCsrfToken()

  const res = await fetch(WORKER_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken,
    },
    body: JSON.stringify({
      action: 'add_order',
      turnstileToken,
      _csrf: csrfToken,
      ...payload,
    }),
  })
  if (!res.ok) {
    // 403 のような明示的エラーの場合はメッセージを取得
    let errMsg = '送信に失敗しました'
    try {
      const errData = await res.json()
      if (errData.message) errMsg = errData.message
    } catch (_) {}
    throw new Error(errMsg)
  }
  const data = await res.json()
  if (data.status !== 'ok') throw new Error(data.message || '送信エラー')
  return data
}
