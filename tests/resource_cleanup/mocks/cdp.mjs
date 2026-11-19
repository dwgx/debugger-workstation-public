import fs from 'node:fs';
import path from 'node:path';
const root = process.env.CLEANUP_CASE_ROOT;
const mode = process.env.CLEANUP_MODE;
const log = event => fs.appendFileSync(path.join(root, 'events.jsonl'), JSON.stringify(event) + '\n');
export class CDP {
  static async connect(url) {
    if (url !== 'ws://owned-mock.invalid') throw new Error('unexpected external connection');
    log({ event: 'cdp.connect', url });
    if (mode === 'connect-fail') throw new Error('MOCK_CONNECT_FAILURE');
    fs.writeFileSync(path.join(root, 'mock-owned-socket'), 'owned connection');
    return new CDP();
  }
  async send(method, params) {
    log({ event: 'cdp.send', method, params });
    if (method === 'Target.createTarget') return { targetId: 'owned-target' };
    if (method === 'Target.attachToTarget') return { sessionId: 'owned-session' };
    return {};
  }
  waitFor() { return Promise.resolve({}); }
  async close() {
    log({ event: 'cdp.close.begin' });
    await new Promise(resolve => setTimeout(resolve, 5));
    fs.unlinkSync(path.join(root, 'mock-owned-socket'));
    log({ event: 'cdp.close.end' });
  }
}
export async function evalInPage() {
  log({ event: 'cdp.evaluate' });
  if (mode === 'evaluate-fail') throw new Error('MOCK_EVALUATE_FAILURE');
  return { title: 'Owned mock page', href: 'http://127.0.0.1:9/fixture',
           nodes: [{ selector: 'p#owned', text: 'owned fixture' }] };
}
