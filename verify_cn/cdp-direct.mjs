// Direct CDP client that uses the DOM domain (not Runtime.evaluate's blocked
// document.querySelector). Bypasses the site's page-context override.
// Usage:
//   node cdp-direct.mjs <cmd> [args]
//   cmds:
//     list                                  list page targets
//     buttons                               list all <button> text+class on the page
//     clickByText <regex>                   click first button whose text matches
//     clickSel <cssSelector>                click first element matching CSS (via DOM domain)
//     html <cssSelector>                    get outerHTML of first match
//     scrollToEnd                           scroll to bottom
// Env: TARGET = page targetId (default 09A185D18F67A3425E2494120AF9A1DF)

const TARGET = process.env.TARGET || '09A185D18F67A3425E2494120AF9A1DF';
const cmd = process.argv[2];
const arg = process.argv[3];

const CDP = 'http://127.0.0.1:9222';

async function getBrowserWs() {
  const r = await fetch(`${CDP}/json/version`);
  const j = await r.json();
  return j.webSocketDebuggerUrl;
}
async function getTargets() {
  const r = await fetch(`${CDP}/json/list`);
  return await r.json();
}

let _id = 0;
function rpc(ws, sessionId, method, params = {}) {
  const id = ++_id;
  return new Promise((resolve, reject) => {
    const h = (ev) => {
      const m = JSON.parse(ev.data);
      if (m.id === id) {
        ws.removeEventListener('message', h);
        if (m.error) reject(new Error(`${method}: ${m.error.message}`));
        else resolve(m.result);
      }
    };
    ws.addEventListener('message', h);
    ws.send(JSON.stringify({ id, method, params, sessionId }));
    setTimeout(() => { ws.removeEventListener('message', h); reject(new Error('timeout ' + method)); }, 30000);
  });
}

async function withSession(fn) {
  const wsUrl = await getBrowserWs();
  const ws = new WebSocket(wsUrl);
  await new Promise(r => ws.addEventListener('open', r, { once: true }));
  const ts = await getTargets();
  const tgt = ts.find(t => t.id === TARGET);
  if (!tgt) throw new Error('target not found: ' + TARGET);
  const attached = await rpc(ws, undefined, 'Target.attachToTarget', { targetId: TARGET, flatten: true });
  const sid = attached.sessionId;
  try {
    return await fn(ws, sid);
  } finally {
    await rpc(ws, sid, 'Target.detachFromTarget', { sessionId: sid }).catch(() => {});
    ws.close();
  }
}

async function getDoc(ws, sid) {
  const d = await rpc(ws, sid, 'DOM.getDocument', { depth: -1, pierce: true });
  return d.root;
}

async function allButtons(ws, sid) {
  const root = await getDoc(ws, sid);
  const q = await rpc(ws, sid, 'DOM.querySelectorAll', { nodeId: root.nodeId, selector: 'button' });
  const out = [];
  for (const nodeId of q.nodeIds) {
    const oh = await rpc(ws, sid, 'DOM.getOuterHTML', { nodeId });
    const html = oh.outerHTML || '';
    const m = html.match(/>([^<]{1,40})<\/button>/);
    const text = m ? m[1].trim() : '';
    const cls = (html.match(/class="([^"]*)"/) || [])[1] || '';
    out.push({ nodeId, text, cls });
  }
  return out;
}

async function findButtonByClass(ws, sid, classFragment) {
  const root = await getDoc(ws, sid);
  const q = await rpc(ws, sid, 'DOM.querySelectorAll', { nodeId: root.nodeId, selector: 'button' });
  for (const nodeId of q.nodeIds) {
    const oh = await rpc(ws, sid, 'DOM.getOuterHTML', { nodeId });
    const html = oh.outerHTML || '';
    if (html.includes(classFragment)) return { nodeId, html };
  }
  return null;
}

async function clickNode(ws, sid, nodeId) {
  await rpc(ws, sid, 'DOM.scrollIntoViewIfNeeded', { nodeId }).catch(() => {});
  await new Promise(r => setTimeout(r, 300));
  const box = await rpc(ws, sid, 'DOM.getBoxModel', { nodeId });
  if (process.env.DEBUG) console.error('BOX', JSON.stringify(box));
  const pts = box.model?.content || box.model?.border || [];
  if (!pts || !pts.length) throw new Error('no box for node ' + nodeId);
  const [{ x, y }] = pts;
  const cx = Math.round(x + (box.model.width || 0) / 2);
  const cy = Math.round(y + (box.model.height || 0) / 2);
  const params = { type: 'mousePressed', x: cx, y: cy, button: 'left', clickCount: 1 };
  try {
    await rpc(ws, sid, 'Input.dispatchMouseEvent', { type: 'mouseMoved', x: cx, y: cy });
    await rpc(ws, sid, 'Input.dispatchMouseEvent', params);
    await rpc(ws, sid, 'Input.dispatchMouseEvent', { ...params, type: 'mouseReleased' });
    return { cx, cy, via: 'mouse' };
  } catch (e) {
    if (process.env.DEBUG) console.error('mouse-click failed, fallback to resolveNode.click():', e.message);
    const resolved = await rpc(ws, sid, 'DOM.resolveNode', { nodeId });
    const objId = resolved.object.objectId;
    await rpc(ws, sid, 'Runtime.callFunctionOn', {
      objectId: objId,
      functionDeclaration: 'function(){ this.click(); }',
      returnByValue: true,
    });
    return { cx, cy, via: 'resolveNode' };
  }
}

async function main() {
  if (cmd === 'list') {
    const ts = await getTargets();
    console.log(JSON.stringify(ts.filter(t => t.type === 'page').map(t => ({ id: t.id, title: t.title, url: t.url })), null, 2));
    return;
  }
  await withSession(async (ws, sid) => {
    if (cmd === 'buttons') {
      const bs = await allButtons(ws, sid);
      console.log(JSON.stringify(bs, null, 2));
    } else if (cmd === 'clickNode') {
      const nodeId = parseInt(arg, 10);
      const p = await clickNode(ws, sid, nodeId);
      console.log('clicked', JSON.stringify(p));
    } else if (cmd === 'clickByClass') {
      const hit = await findButtonByClass(ws, sid, arg);
      if (!hit) { console.log('NO MATCH for class fragment:', arg); return; }
      console.log('clicking class-match', JSON.stringify({ nodeId: hit.nodeId, snippet: hit.html.slice(0, 120) }));
      const p = await clickNode(ws, sid, hit.nodeId);
      console.log('clicked', JSON.stringify(p));
    } else if (cmd === 'clickByText') {
      const bs = await allButtons(ws, sid);
      const re = new RegExp(arg);
      const hit = bs.find(b => re.test(b.text));
      if (!hit) { console.log('NO MATCH among:', JSON.stringify(bs.map(b => b.text))); return; }
      console.log('clicking:', JSON.stringify(hit));
      const p = await clickNode(ws, sid, hit.nodeId);
      console.log('clicked at', p);
    } else if (cmd === 'scrollToEnd') {
      await rpc(ws, sid, 'Runtime.evaluate', { expression: 'window.scrollTo(0, document.body.scrollHeight)', returnByValue: true });
      console.log('scrolled');
    } else if (cmd === 'html') {
      const root = await getDoc(ws, sid);
      const q = await rpc(ws, sid, 'DOM.querySelectorAll', { nodeId: root.nodeId, selector: arg });
      for (const nodeId of q.nodeIds.slice(0, 3)) {
        const oh = await rpc(ws, sid, 'DOM.getOuterHTML', { nodeId });
        console.log(oh.outerHTML ? oh.outerHTML.slice(0, 800) : '(empty)');
        console.log('----');
      }
    } else if (cmd === 'box') {
      const nodeId = parseInt(arg, 10);
      const box = await rpc(ws, sid, 'DOM.getBoxModel', { nodeId });
      console.log('BOX', JSON.stringify(box));
    } else {
      console.log('unknown cmd:', cmd);
    }
  });
}

main().catch(e => { console.error('ERR', e.message); process.exit(1); });
