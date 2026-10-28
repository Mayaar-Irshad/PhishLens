// Imported by explicit path so bundlers and Node never resolve the deprecated
// built-in `punycode` module instead of the npm package.
declare module 'punycode/punycode.es6.js' {
  export function toUnicode(input: string): string;
  export function toASCII(input: string): string;
}
