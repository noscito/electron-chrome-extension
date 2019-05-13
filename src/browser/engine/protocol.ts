import { app, protocol } from 'electron';
import { readFileSync, createReadStream } from 'fs';
import stream from 'stream';
import { lookup } from 'mime-types';
import { join } from 'path';
import { parse } from 'url';

import { Protocol } from '../../common';
import { getExtensionById } from '../chrome-extension';
import { protocolAsScheme } from '../../common/utils';

/*
Protocol.ts

Everything related to `chrome-extension://` protocol goes here

- Register protocol
- Handle and serve extension web resources and background page
*/

// defaultContentSecurityPolicy match Chromium kDefaultContentSecurityPolicy
// https://cs.chromium.org/chromium/src/extensions/common/manifest_handlers/csp_info.cc?l=31
// tslint:disable-next-line: max-line-length
const defaultContentSecurityPolicy = 'script-src \'self\' blob: filesystem: chrome-extension-resource:; object-src \'self\' blob: filesystem:;';

(protocol as any).registerStandardSchemes(
  [protocolAsScheme(Protocol.Extension)],
  { secure: true }
);

const protocolHandler = async (
  h: Electron.RegisterBufferProtocolRequest,
  callback: Function
) => {
  console.log(h);
  const { url } = h;
  const { hostname, pathname } = parse(url);
  if (!hostname || !pathname) return callback();

  const extension = getExtensionById(hostname);
  if (!extension) return callback();

  const { src, backgroundPage: { name, html } } = extension;

  const manifestPath = join(src, 'manifest.json');
  const manifestFile = await readFileSync(manifestPath, 'utf-8');
  const manifest = JSON.parse(manifestFile);

  const headers = {};

  // Always send CORS
  // refs:
  // https://cs.chromium.org/chromium/src/extensions/browser/extension_protocols.cc?l=524
  // https://cs.chromium.org/chromium/src/extensions/browser/extension_protocols.cc?l=330
  // https://cs.chromium.org/chromium/src/extensions/browser/extension_protocols.cc?l=1017
  headers['access-control-allow-origin'] = '*';

  // Set Content Security Policy for Chrome Extensions
  const manifestContentSecurityPolicy = manifest.content_security_policy;
  const contentSecurityPolicy = manifestContentSecurityPolicy ? manifestContentSecurityPolicy : defaultContentSecurityPolicy;

  headers['content-security-policy'] = contentSecurityPolicy;

  // Check if we serve the background page (html)
  if (`/${name}` === pathname) {
    headers['content-type'] = 'text/html';

    // Transform a Buffer into a Stream (expected in callback)
    // Stream callback allow custom headers
    return callback({
      statusCode: 200,
      headers,
      data: (new stream.PassThrough()).end(html),
    });
  }

  // const accessibleResources = manifest.web_accessible_resources;
  // const isResourceAccessible = accessibleResources.includes(pathname.replace(/^\/+/g, '')); // remove leading slash for relative url

  // check inner related scripts and assets

  // webRequest doesn't work
  // we don't have the referrer

  // if (!isResourceAccessible) {
  //   return callback({
  //     statusCode: 403,
  //     headers,
  //   });
  // }

  // Create file stream
  const uri = join(src, pathname);
  const data = createReadStream(uri);

  // Set Mime type
  const mimeType = lookup(pathname);
  if (mimeType) headers['content-type'] = mimeType;

  return callback({
    statusCode: 200,
    headers,
    data,
  });
};

app.on('session-created', (session) => {
  if (Protocol.Extension === Protocol.ExtensionDefault) {
    session.protocol.unregisterProtocol(
      protocolAsScheme(Protocol.ExtensionDefault)
    );
  }

  session.protocol.registerStreamProtocol(
    protocolAsScheme(Protocol.Extension),
    protocolHandler,
    (error: any) => {
      if (error) {
        console.error(
          `Unable to register ${Protocol.Extension} protocol: ${error}`
        );
      }
    }
  );
});
