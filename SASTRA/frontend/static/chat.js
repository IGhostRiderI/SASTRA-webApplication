(function () {
  'use strict';

  var chatHistory = [];

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
        throw new Error(errData.detail || 'AI service error.');
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
