import React, { useState } from 'react'
import { fetchProperty, submitOrder } from './orderData'

// ── 商品定義（価格は物件マスターから上書き） ──────────────────
const KEY_ITEMS = [
  { id: 'tebra',     name: 'Tebraキー',   priceKey: 'Tebraキー価格',   note: 'THKY-02L' },
  { id: 'storage',   name: '収納キー',     priceKey: '収納キー価格',    note: '新旧あり' },
  { id: 'f22tl',     name: 'F22 TLキー',  priceKey: 'F22TLキー価格',   note: 'TLKY-01' },
  { id: 'f22std',    name: 'F22 標準キー', priceKey: 'F22標準キー価格', note: '' },
]
const FEE_ITEMS = [
  { id: 'dispatch',  name: '出張費',       priceKey: '出張費',       optional: true },
  { id: 'shared',    name: '共用部登録費', priceKey: '共用部登録費', optional: true },
  { id: 'exchange',  name: '交換費',       priceKey: '交換費',       optional: true, autoWith: 'storage' },
  { id: 'admin',     name: '事務手数料',   priceKey: '事務手数料',   optional: false },
  { id: 'private',   name: '専有部登録費', priceKey: '専有部登録費', optional: true },
]

function initCart() {
  return { admin: 1 }
}

export default function OrderPage() {
  const [step,       setStep]       = useState(1)   // 1:PASS入力 2:商品選択 3:依頼者情報 4:完了
  const [passInput,  setPassInput]  = useState('')
  const [property,   setProperty]   = useState(null)
  const [loading,    setLoading]    = useState(false)
  const [error,      setError]      = useState('')
  const [cart,       setCart]       = useState(initCart())  // { itemId: qty }
  const [form,       setForm]       = useState({ name: '', room: '', phone: '', note: '' })
  const [submitting, setSubmitting] = useState(false)

  // ── PASS照合 ──────────────────────────────────────
  async function handlePassSubmit(e) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const prop = await fetchProperty(passInput.trim())
      setProperty(prop)
      setCart(initCart())
      setStep(2)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  // ── カート操作 ────────────────────────────────────
  function getPrice(priceKey) {
    if (!property) return 0
    return Number(property[priceKey]) || 0
  }
  function setQty(id, delta) {
    setCart(prev => {
      const next = { ...prev }
      const cur  = next[id] || 0
      const val  = Math.max(0, cur + delta)
      if (val === 0) delete next[id]
      else next[id] = val
      // 収納キー → 交換費を自動ON
      if (id === 'storage') {
        if (val > 0) next['exchange'] = 1
        else delete next['exchange']
      }
      return next
    })
  }
  function totalPrice() {
    let total = 0
    ;[...KEY_ITEMS, ...FEE_ITEMS].forEach(item => {
      const qty = cart[item.id] || 0
      if (qty > 0) total += getPrice(item.priceKey) * qty
    })
    return total
  }
  function cartSummary() {
    const lines = []
    ;[...KEY_ITEMS, ...FEE_ITEMS].forEach(item => {
      const qty = cart[item.id] || 0
      if (qty > 0) {
        lines.push(qty > 1 ? `${item.name} ×${qty}` : item.name)
      }
    })
    return lines.join('、')
  }

  // ── 注文送信 ──────────────────────────────────────
  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    setSubmitting(true)
    const items = []
    ;[...KEY_ITEMS, ...FEE_ITEMS].forEach(item => {
      const qty = cart[item.id] || 0
      if (qty > 0) items.push({ name: item.name, qty, price: getPrice(item.priceKey) })
    })
    try {
      await submitOrder({
        status:   'inquiry',
        maker:    'シブタニ',
        mansion:  property['物件名'] || '',
        room:     form.room,
        name:     form.name,
        phone:    form.phone,
        work:     cartSummary(),
        amount:   totalPrice(),
        items:    JSON.stringify(items),
        note:     form.note,
        passCode: passInput.trim(),
        createdAt: new Date().toISOString(),
      })
      setStep(4)
    } catch (err) {
      setError(err.message)
    } finally {
      setSubmitting(false)
    }
  }

  // ── UI ────────────────────────────────────────────
  return (
    <div className="clh-wrap">
      <header className="clh-header">
        <div className="clh-logo">CLH</div>
        <div className="clh-title">合鍵オンライン注文</div>
      </header>

      {/* ステップ1: PASSコード入力 */}
      {step === 1 && (
        <div className="clh-card">
          <h2 className="clh-card-title">PASSコードを入力</h2>
          <p className="clh-hint">引き渡し書類に記載のPASSコード（数字6桁）を入力してください。</p>
          <form onSubmit={handlePassSubmit}>
            <input
              className="clh-input"
              type="text"
              inputMode="numeric"
              placeholder="例: 537847"
              maxLength={8}
              value={passInput}
              onChange={e => setPassInput(e.target.value)}
              required
            />
            {error && <p className="clh-error">{error}</p>}
            <button className="clh-btn" type="submit" disabled={loading}>
              {loading ? '照合中...' : '次へ →'}
            </button>
          </form>
          <p className="clh-small">PASSコードは入居時の引き渡し書類に記載されています。<br />ご不明な場合は管理会社へお問い合わせください。</p>
        </div>
      )}

      {/* ステップ2: 商品選択 */}
      {step === 2 && property && (
        <div className="clh-card">
          <div className="clh-property-badge">
            <span className="clh-badge-label">物件</span>
            <span className="clh-badge-name">{property['物件名']}</span>
          </div>
          {property['住所'] && <p className="clh-address">{property['住所']}</p>}
          {property['システム'] && <p className="clh-system">🔑 {property['システム']}</p>}

          <h3 className="clh-section-title">キーを選択</h3>
          <div className="clh-item-list">
            {KEY_ITEMS.map(item => {
              const price = getPrice(item.priceKey)
              if (!price) return null
              const qty = cart[item.id] || 0
              return (
                <div key={item.id} className={`clh-item${qty > 0 ? ' selected' : ''}`}>
                  <div className="clh-item-info">
                    <span className="clh-item-name">{item.name}</span>
                    {item.note && <span className="clh-item-note">{item.note}</span>}
                  </div>
                  <div className="clh-item-right">
                    <span className="clh-item-price">¥{price.toLocaleString()}</span>
                    <div className="clh-qty">
                      <button type="button" className="clh-qty-btn" onClick={() => setQty(item.id, -1)}>－</button>
                      <span className={`clh-qty-num${qty > 0 ? ' active' : ''}`}>{qty}</span>
                      <button type="button" className="clh-qty-btn plus" onClick={() => setQty(item.id, 1)}>＋</button>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>

          <h3 className="clh-section-title">費用</h3>
          <div className="clh-item-list">
            {FEE_ITEMS.map(item => {
              const price = getPrice(item.priceKey)
              if (!price) return null
              const qty   = cart[item.id] || 0
              const fixed = !item.optional
              return (
                <div key={item.id} className={`clh-item fee${qty > 0 ? ' selected' : ''}${fixed ? ' fixed' : ''}`}>
                  <div className="clh-item-info">
                    <span className="clh-item-name">{item.name}</span>
                    {fixed && <span className="clh-item-tag">必須</span>}
                    {item.autoWith === 'storage' && cart['storage'] > 0 && (
                      <span className="clh-item-tag auto">自動追加</span>
                    )}
                  </div>
                  <div className="clh-item-right">
                    <span className="clh-item-price">¥{price.toLocaleString()}</span>
                    {fixed ? (
                      <span className="clh-qty-fixed">×1</span>
                    ) : item.autoWith === 'storage' && cart['storage'] > 0 ? (
                      <span className="clh-qty-fixed">×1</span>
                    ) : (
                      <div className="clh-qty">
                        <button type="button" className="clh-qty-btn" onClick={() => setQty(item.id, -1)}>－</button>
                        <span className={`clh-qty-num${qty > 0 ? ' active' : ''}`}>{qty}</span>
                        <button type="button" className="clh-qty-btn plus" onClick={() => setQty(item.id, 1)}>＋</button>
                      </div>
                    )}
                  </div>
                </div>
              )
            })}
          </div>

          <div className="clh-total">
            <span>合計（税込）</span>
            <span className="clh-total-price">¥{totalPrice().toLocaleString()}</span>
          </div>

          {error && <p className="clh-error">{error}</p>}
          <button
            className="clh-btn"
            onClick={() => { setError(''); setStep(3) }}
            disabled={totalPrice() === 0}
          >
            依頼者情報を入力 →
          </button>
          <button className="clh-btn-sub" onClick={() => setStep(1)}>← PASSコード入力に戻る</button>
        </div>
      )}

      {/* ステップ3: 依頼者情報 */}
      {step === 3 && (
        <div className="clh-card">
          <h2 className="clh-card-title">依頼者情報を入力</h2>
          <form onSubmit={handleSubmit}>
            <label className="clh-label">お名前 <span className="req">*</span></label>
            <input
              className="clh-input"
              type="text"
              placeholder="山田 太郎"
              value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
              required
            />
            <label className="clh-label">部屋番号 <span className="req">*</span></label>
            <input
              className="clh-input"
              type="text"
              placeholder="例: 301"
              value={form.room}
              onChange={e => setForm(f => ({ ...f, room: e.target.value }))}
              required
            />
            <label className="clh-label">電話番号 <span className="req">*</span></label>
            <input
              className="clh-input"
              type="tel"
              placeholder="090-0000-0000"
              value={form.phone}
              onChange={e => setForm(f => ({ ...f, phone: e.target.value }))}
              required
            />
            <label className="clh-label">備考 <span className="opt">（任意）</span></label>
            <textarea
              className="clh-input clh-textarea"
              placeholder="ご要望・ご質問があればご記入ください"
              value={form.note}
              onChange={e => setForm(f => ({ ...f, note: e.target.value }))}
              rows={3}
            />

            <div className="clh-confirm-box">
              <p className="clh-confirm-title">ご注文内容</p>
              <p className="clh-confirm-mansion">{property?.['物件名']}</p>
              <p className="clh-confirm-items">{cartSummary()}</p>
              <p className="clh-confirm-total">合計 ¥{totalPrice().toLocaleString()}（税込）</p>
            </div>

            {error && <p className="clh-error">{error}</p>}
            <button className="clh-btn" type="submit" disabled={submitting}>
              {submitting ? '送信中...' : '注文を送信する'}
            </button>
            <button type="button" className="clh-btn-sub" onClick={() => setStep(2)}>← 商品選択に戻る</button>
          </form>
        </div>
      )}

      {/* ステップ4: 完了 */}
      {step === 4 && (
        <div className="clh-card clh-done">
          <div className="clh-done-icon">✅</div>
          <h2 className="clh-card-title">注文を受け付けました</h2>
          <p className="clh-done-text">
            ご注文ありがとうございます。<br />
            担当者よりご連絡いたします。<br />
            通常2〜4週間程度お時間をいただいております。
          </p>
          <p className="clh-done-contact">
            お急ぎの場合はお電話にてお問い合わせください。
          </p>
        </div>
      )}

      <footer className="clh-footer">
        <p>カーロックホームズ株式会社</p>
        <p>© 2025 CAR LOCK HOLMES CO., LTD.</p>
      </footer>
    </div>
  )
}
