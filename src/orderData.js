const WORKER_URL  = 'https://web-order.clh-0556-clh.workers.dev'
// No.4是正(2026-04-14): APIキー直書き削除 → Worker側でOrigin検証に変更

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
 */
export async function submitOrder(payload) {
  const res = await fetch(WORKER_URL, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ action: 'add_order', ...payload }),
  })
  if (!res.ok) throw new Error('送信に失敗しました')
  const data = await res.json()
  if (data.status !== 'ok') throw new Error(data.message || '送信エラー')
  return data
}
