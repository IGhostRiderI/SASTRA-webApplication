(function () {
  'use strict';

  var chatHistory = [];

  function ensureAppPopup() {
    var popup = document.getElementById('app-popup') || document.getElementById('chat-app-popup');
    if (popup) return popup;

    if (!document.getElementById('chat-app-popup-style')) {
      var style = document.createElement('style');
      style.id = 'chat-app-popup-style';
      style.textContent = '' +
        '.chat-app-popup{position:fixed;top:88px;right:20px;min-width:300px;max-width:460px;background:rgba(255,255,255,.96);backdrop-filter:blur(12px);border:1px solid rgba(239,68,68,.25);box-shadow:0 10px 30px rgba(15,23,42,.16);border-radius:14px;padding:14px 16px;display:none;align-items:flex-start;gap:10px;z-index:1200;}' +
        '.chat-app-popup.show{display:flex;}' +
        '.chat-app-popup.error{border-left:4px solid #dc2626;}' +
        '.chat-app-popup-icon{width:22px;height:22px;border-radius:999px;background:rgba(220,38,38,.1);color:#dc2626;font-weight:800;font-family:Sora,sans-serif;display:inline-flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:1px;}' +
        '.chat-app-popup-text{font-size:.84rem;line-height:1.45;color:#111827;flex:1;font-weight:600;}' +
        '.chat-app-popup-close{border:none;background:transparent;color:#6b7280;cursor:pointer;font-size:1rem;line-height:1;padding:2px 4px;flex-shrink:0;}';
      document.head.appendChild(style);
    }

    popup = document.createElement('div');
    popup.id = 'chat-app-popup';
    popup.className = 'chat-app-popup';
    popup.setAttribute('role', 'alert');
    popup.setAttribute('aria-live', 'assertive');
    popup.innerHTML = '<div class="chat-app-popup-icon">!</div><div class="chat-app-popup-text" id="chat-app-popup-text"></div><button class="chat-app-popup-close" id="chat-app-popup-close" aria-label="Close message">x</button>';
    document.body.appendChild(popup);
    popup.querySelector('#chat-app-popup-close').addEventListener('click', function () {
      popup.classList.remove('show');
    });
    return popup;
  }

  function showAppPopup(message) {
    var popup = ensureAppPopup();
    var textEl = popup.querySelector('#app-popup-text') || popup.querySelector('#chat-app-popup-text');
    if (!textEl) return;
    textEl.textContent = message;
    popup.classList.add('show', 'error');
  }

  function escapeHtml(t) {
    return t.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  function renderMarkdown(text) {
    var s = escapeHtml(text);
    // code blocks (```...```)
    s = s.replace(/```[\w]*\n?([\s\S]*?)```/g, '<pre><code>$1</code></pre>');
    // inline code
    s = s.replace(/`([^`]+)`/g, '<code>$1</code>');
    // bold
    s = s.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    // italic
    s = s.replace(/\*(.+?)\*/g, '<em>$1</em>');
    // newlines
    s = s.replace(/\n/g, '<br>');
    return s;
  }

  function getChatBody() {
    return document.getElementById('chatMessages');
  }

  function scrollDown() {
    var body = getChatBody();
    if (body) body.scrollTop = body.scrollHeight;
  }

  function addMessage(role, text) {
    var body = getChatBody();
    if (!body) return null;

    var row = document.createElement('div');
    row.className = 'chat-msg chat-msg-' + role;

    var bubble = document.createElement('div');
    bubble.className = 'chat-msg-bubble';
    bubble.innerHTML = renderMarkdown(text);

    row.appendChild(bubble);
    body.appendChild(row);
    scrollDown();
    return bubble;
  }

  function showTyping() {
    var body = getChatBody();
    if (!body) return null;
    var row = document.createElement('div');
    row.className = 'chat-msg chat-msg-ai';
    row.id = 'chatTypingRow';
    row.innerHTML = '<div class="chat-typing-wrap"><span></span><span></span><span></span></div>';
    body.appendChild(row);
    scrollDown();
    return row;
  }

  function removeTyping() {
    var el = document.getElementById('chatTypingRow');
    if (el) el.remove();
  }

  async function sendChatMessage() {
    var input = document.getElementById('chatInput');
    var sendBtn = document.getElementById('chatSend');
    if (!input || !sendBtn) return;

    var msg = input.value.trim();
    if (!msg || sendBtn.disabled) return;

    input.value = '';
    input.disabled = true;
    sendBtn.disabled = true;

    addMessage('user', msg);
    showTyping();

    try {
      var res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ message: msg, history: chatHistory }),
      });

      if (!res.ok) {
        var errData = await res.json().catch(function () { return {}; });
        if (res.status === 429 && errData && errData.detail && errData.detail.code === 'LLM_RATE_LIMIT_REACHED') {
          var retrySeconds = Number(errData.detail.retry_after_seconds || 0);
          var retryMinutes = retrySeconds > 0 ? Math.ceil(retrySeconds / 60) : null;
          var waitHint = retryMinutes ? (' Try again in about ' + retryMinutes + ' minute' + (retryMinutes === 1 ? '' : 's') + '.') : '';
          showAppPopup('AI request limit reached. You can send up to 10 requests per minute.' + waitHint);
        }
        var detailMessage = (typeof errData.detail === 'string')
          ? errData.detail
          : (errData.detail && errData.detail.message) || 'AI service error.';
        throw new Error(detailMessage);
      }

      removeTyping();
      var bubble = addMessage('ai', '');

      var reader = res.body.getReader();
      var decoder = new TextDecoder();
      var aiText = '';
      var buf = '';

      while (true) {
        var chunk = await reader.read();
        if (chunk.done) break;

        buf += decoder.decode(chunk.value, { stream: true });
        var lines = buf.split('\n');
        buf = lines.pop();

        for (var i = 0; i < lines.length; i++) {
          var line = lines[i];
          if (!line.startsWith('data: ')) continue;
          var data = line.slice(6).trim();
          if (data === '[DONE]') continue;
          try {
            var parsed = JSON.parse(data);
            if (parsed.token) {
              aiText += parsed.token;
              bubble.innerHTML = renderMarkdown(aiText);
              scrollDown();
            }
          } catch (_) {}
        }
      }

      chatHistory.push({ role: 'user', content: msg });
      chatHistory.push({ role: 'assistant', content: aiText });

    } catch (err) {
      removeTyping();
      addMessage('ai', '⚠ ' + (err.message || 'Something went wrong. Please try again.'));
    } finally {
      input.disabled = false;
      sendBtn.disabled = false;
      input.focus();
    }
  }

  window.sendChatMessage = sendChatMessage;

  document.addEventListener('DOMContentLoaded', function () {
    var input = document.getElementById('chatInput');
    if (input) {
      input.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' && !e.shiftKey) {
          e.preventDefault();
          sendChatMessage();
        }
      });
    }
  });
})();
