// Ported from AdaptixC2 (https://github.com/Adaptix-Framework/AdaptixC2),
// AdaptixServer/extenders/beacon_agent/src_beacon/beacon/Crypt.cpp (RC4, key schedule identical) — GPLv3, (c) the
// AdaptixC2 authors. Structural fidelity is deliberate; deviations are noted inline.
// rc4.js — standalone RC4 (matches Adaptix Beacon Crypt.cpp).
// Node's crypto no longer provides RC4, so implement it (identical to the C++ beacon).
function rc4Init(key) {
  const S = new Uint8Array(256);
  for (let i = 0; i < 256; i++) S[i] = i;
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + S[i] + key[i % key.length]) & 0xff;
    const t = S[i]; S[i] = S[j]; S[j] = t;
  }
  return S;
}

function rc4Run(data, key) {
  const S = rc4Init(key);
  let i = 0, j = 0;
  const out = Buffer.alloc(data.length);
  for (let k = 0; k < data.length; k++) {
    i = (i + 1) & 0xff;
    j = (j + S[i]) & 0xff;
    const t = S[i]; S[i] = S[j]; S[j] = t;
    out[k] = data[k] ^ S[(S[i] + S[j]) & 0xff];
  }
  return out;
}

module.exports = { rc4: rc4Run, rc4Init };
