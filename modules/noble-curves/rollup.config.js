import resolve from '@rollup/plugin-node-resolve';
import inject from '@rollup/plugin-inject';

export default {
  input: 'harness.js',
  external: ['TextEncoder'],
  output: {
    file: 'noble-curves.js',
    format: 'cjs',
    preferConst: true,
  },

  plugins: [
    inject({
      TextEncoder: ['@zxing/text-encoding', 'TextEncoder'],
    }),
    resolve({ browser: true }),
  ],
};
