var exports = {};
var module = {};
var window = {};
window.crypto = {};
window.crypto.getRandomValues = Math.random;

function require(which) {
    if ( which != 'crypto' ) {
        throw 'Required something other than crypto';
    }
    return [];
}
