const WORKER_URL  = 'https://web-order.clh-0556-clh.workers.dev'
const API_KEY     = 'CLH-ORDER-2025-XK9'

/**
 * PASSコードから物件情報を取得
 */
export async function fetchProperty(passCode) {
  const res = await fetch(
    `${WORKER_URL}/property?pass=${encodeURIComponent(passCode)}&key=${API_KEY}`
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
