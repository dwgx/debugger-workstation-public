import fs from 'node:fs';
import path from 'node:path';
const root = process.env.CLEANUP_CASE_ROOT;
const log = event => fs.appendFileSync(path.join(root, 'events.jsonl'), JSON.stringify(event) + '\n');
export async function launchChrome(options) {
  log({ event: 'chrome.launch', owner: 'test-created', options });
  const profile = path.join(root, 'mock-owned-profile');
  fs.mkdirSync(profile);
  fs.writeFileSync(path.join(profile, 'owned.txt'), 'owned mock profile');
  return { wsUrl: 'ws://owned-mock.invalid', close: async () => {
    log({ event: 'chrome.close.begin', owner: 'test-created' });
    await new Promise(resolve => setTimeout(resolve, 5));
    fs.rmSync(profile, { recursive: true });
    log({ event: 'chrome.close.end', owner: 'test-created' });
  } };
}
