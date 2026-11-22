/**
 * Telegram's production RSA public keys — public information published in
 * Telegram's clients and documentation. Embedding them keeps reqly fully self
 * contained: no MTProto library is needed to derive an auth key on a new DC.
 *
 * Each key is verified by recomputing its fingerprint from TL-serialized n/e
 * (see tests/rsa-key.test.ts). A truncated or mislabelled modulus would be
 * rejected by the server during req_DH_params, so the guard is essential.
 *
 * The first two are the keys historically published in the auth-key example;
 * the last two are the pair currently advertised by production DCs.
 */

import { rsaKeyFromBytes, type RsaPublicKey } from "./handshake"

export interface RsaKeyMaterial {
  n: Uint8Array
  e: Uint8Array
  fingerprint: bigint
}

function decodeHex(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/i, "")
  if (clean.length % 2) throw new Error("reqly: malformed RSA key hex")
  const out = new Uint8Array(clean.length / 2)
  for (let index = 0; index < out.length; index += 1) out[index] = Number.parseInt(clean.slice(index * 2, index * 2 + 2), 16)
  return out
}

/** fingerprint (signed int64) → 256-byte modulus, big-endian. */
const PRODUCTION_KEYS: ReadonlyArray<readonly [string, bigint]> = [
  [
    // 0xD09D1D85DE64FD85 — key used by the official auth-key example.
    "e8bb3305c0b52c6cf2afdf7637313489e63e05268e5badb601af417786472e5f93b85438968e20e6729a301c0afc121bf7151f834436f7fda680847a66bf64accec78ee21c0b316f0edafe2f41908da7bd1f4a5107638eeb67040ace472a14f90d9f7c2b7def99688ba3073adb5750bb02964902a359fe745d8170e36876d4fd8a5d41b2a76cbff9a13267eb9580b2d06d10357448d20d9da2191cb5d8c93982961cdfdeda629e37f1fb09a0722027696032fe61ed663db7a37f6f263d370f69db53a0dc0a1748bdaaff6209d5645485e6e001d1953255757e4b8e42813347b11da6ab500fd0ace7e6dfa3736199ccaf9397ed0745a427dcfa6cd67bcb1acff3",
    -3414540481677951611n,
  ],
  [
    // 0xB25898DF208D2603 — second legacy production key.
    "c8c11d635691fac091dd9489aedced2932aa8a0bcefef05fa800892d9b52ed03200865c9e97211cb2ee6c7ae96d3fb0e15aeffd66019b44a08a240cfdd2868a85e1f54d6fa5deaa041f6941ddf302690d61dc476385c2fa655142353cb4e4b59f6e5b6584db76fe8b1370263246c010c93d011014113ebdf987d093f9d37c2be48352d69a1683f8f6e6c2167983c761e3ab169fde5daaa12123fa1beab621e4da5935e9c198f82f35eae583a99386d8110ea6bd1abb0f568759f62694419ea5f69847c43462abef858b4cb5edc84e7b9226cd7bd7e183aa974a712c079dde85b9dc063b8a5c08e8f859c0ee5dcd824c7807f20153361a7f63cfd2a433a1be7f5",
    -5595554452916591101n,
  ],
  [
    // 0x0BC35F3509F7B7A5 — current production key.
    "AEEC36C8FFC109CB099624685B97815415657BD76D8C9C3E398103D7AD16C9BBA6F525ED0412D7AE2C2DE2B44E77D72CBF4B7438709A4E646A05C43427C7F184DEBF72947519680E651500890C6832796DD11F772C25FF8F576755AFE055B0A3752C696EB7D8DA0D8BE1FAF38C9BDD97CE0A77D3916230C4032167100EDD0F9E7A3A9B602D04367B689536AF0D64B613CCBA7962939D3B57682BEB6DAE5B608130B2E52ACA78BA023CF6CE806B1DC49C72CF928A7199D22E3D7AC84E47BC9427D0236945D10DBD15177BAB413FBF0EDFDA09F014C7A7DA088DDE9759702CA760AF2B8E4E97CC055C617BD74C3D97008635B98DC4D621B4891DA9FB0473047927",
    847625836280919973n,
  ],
  [
    // 0xC3B42B026CE86B21 — current production key.
    "C150023E2F70DB7985DED064759CFECF0AF328E69A41DAF4D6F01B538135A6F91F8F8B2A0EC9BA9720CE352EFCF6C5680FFC424BD634864902DE0B4BD6D49F4E580230E3AE97D95C8B19442B3C0A10D8F5633FECEDD6926A7F6DAB0DDB7D457F9EA81B8465FCD6FFFEED114011DF91C059CAEDAF97625F6C96ECC74725556934EF781D866B34F011FCE4D835A090196E9A5F0E4449AF7EB697DDB9076494CA5F81104A305B6DD27665722C46B60E5DF680FB16B210607EF217652E60236C255F6A28315F4083A96791D7214BF64C1DF4FD0DB1944FB26A2A57031B32EEE64AD15A8BA68885CDE74A5BFC920F6ABF59BA5C75506373E7130F9042DA922179251F",
    -4344800451088585951n,
  ],
]

const EXPONENT = decodeHex("010001")

export const TELEGRAM_RSA_KEYS: RsaKeyMaterial[] = PRODUCTION_KEYS.map(([hex, fingerprint]) => ({
  n: decodeHex(hex),
  e: EXPONENT,
  fingerprint,
}))

/** Returns the public key whose fingerprint the server advertised, if known. */
export async function findTelegramKey(fingerprint: bigint): Promise<RsaPublicKey | undefined> {
  const material = TELEGRAM_RSA_KEYS.find((key) => key.fingerprint === fingerprint)
  if (!material) return undefined
  const key = await rsaKeyFromBytes(material.n, material.e)
  if (key.fingerprint !== fingerprint) throw new Error("reqly: embedded RSA key fingerprint mismatch")
  return key
}
// Mellouki Jamal — Asynctric
