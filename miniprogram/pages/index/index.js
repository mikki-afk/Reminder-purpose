// REPLACE with your deployed Cloudflare Worker domain (no trailing slash).
// Also add this domain in 微信公众平台 → 小程序 → 开发管理 → 服务器域名 → request 合法域名.
const WORKER_URL = 'https://your-worker.workers.dev';

Page({
  data: {
    messages: [],
    input: '',
    loading: false,
    scrollTo: '',
    sessionId: '',
  },

  onLoad() {
    let sessionId = wx.getStorageSync('sessionId');
    if (!sessionId) {
      sessionId = `s_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
      wx.setStorageSync('sessionId', sessionId);
    }
    this.setData({ sessionId });
  },

  onInput(e) {
    this.setData({ input: e.detail.value });
  },

  onSend() {
    const text = this.data.input.trim();
    if (!text || this.data.loading) return;

    const userMsg = { id: `u${Date.now()}`, role: 'user', content: text };
    this.setData({
      messages: [...this.data.messages, userMsg],
      input: '',
      loading: true,
      scrollTo: userMsg.id,
    });

    wx.request({
      url: `${WORKER_URL}/chat`,
      method: 'POST',
      header: { 'Content-Type': 'application/json' },
      data: { message: text, sessionId: this.data.sessionId },
      success: (res) => {
        const reply = (res.data && res.data.reply) || '(空回复)';
        const asstMsg = { id: `a${Date.now()}`, role: 'assistant', content: reply };
        this.setData({
          messages: [...this.data.messages, asstMsg],
          loading: false,
          scrollTo: asstMsg.id,
        });
      },
      fail: () => {
        this.setData({ loading: false });
        wx.showToast({ title: '请求失败', icon: 'error' });
      },
    });
  },
});
