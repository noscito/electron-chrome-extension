import assert from 'assert';

import { Window } from '../../src/common/apis/windows';

describe('chrome.windows', () => {
  before(() => {
    require('../../src/renderer/chrome-api').injectTo('test', false, window);
  });

  it('API Available', () => {
    const namespace = window.chrome.windows;

    assert.strictEqual(Boolean(namespace), true);
  });

  it('Create Window', () => {
    const win = {
      url: 'google.com',
    };

    window.chrome.windows.create(
      win,
      (w: Window) => {
        assert.notStrictEqual(w.id, undefined);
      }
    );
  });

  it('Get Current Window', () => {
    window.chrome.windows.getCurrent(
      {},
      (w: Window) => {
        assert.notStrictEqual(w.id, undefined);
      }
    );
  });
});
