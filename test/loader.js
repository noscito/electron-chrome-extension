const glob = require('glob');
const { join, resolve } = require('path');

const rendererTests = join(__dirname, '..', 'lib', 'test', '**/*.js');

for (const path of glob.sync(rendererTests)) {
  if (!path.endsWith('.main.js')) {
    console.log('Loading renderer test', path);
    require(resolve(path));
  }
}
