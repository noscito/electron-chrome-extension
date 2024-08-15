import assert from 'assert';

import DownloadProvider from '../../src/browser/fetcher/download-provider';

import {
  EXAMPLE_EXTENSION_ID,
} from './constants';

const fs = require('fs').promises;

describe('Default Download Provider', () => {
  describe('downloading', () => {
    it('can download a crx archive with an ID', async () => {
      const downloader = new DownloadProvider();
      const dlDescriptor = await downloader.downloadById(EXAMPLE_EXTENSION_ID);
      const crxInfo = await fs.stat(dlDescriptor.location.path);

      assert.strictEqual(crxInfo.isFile(), true);
      assert.notStrictEqual(crxInfo.size, 0);
    });
  });

  describe('clean up', () => {
    it('remembers and removes a temp dir', () => {
      // todo
    });

    it('fails graciously if extension doe not exists', () => {
      // todo
    });
  });

  describe('get update infos', () => {
    it('fetches an update xml from a CxInfos', () => {
      // todo
    });

    it('throws an error if no update url is present', () => {
      // todo
    });

    it('throws an error if fetch fails', () => {
      // todo
    });
  });
});
