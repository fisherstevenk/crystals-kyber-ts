import {Buffer} from "buffer";
import {SHA3, SHAKE} from "sha3";
import {Utilities} from "../lib/utilities";
import {Indcpa} from "../lib/indcpa";

/**
 * Abstract class for Kyber implementation
 */
export abstract class KyberService {
    public indcpa: Indcpa;

    public static nttZetas = [
        2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962,
        2127, 1855, 1468, 573, 2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017,
        732, 608, 1787, 411, 3124, 1758, 1223, 652, 2777, 1015, 2036, 1491, 3047,
        1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469, 2476, 3239, 3058, 830,
        107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054, 2226,
        430, 555, 843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574,
        1653, 3083, 778, 1159, 3182, 2552, 1483, 2727, 1119, 1739, 644, 2457, 349,
        418, 329, 3173, 3254, 817, 1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193,
        1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819, 2475, 2459,
        478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628];


    public static nttZetasInv = [
        1701, 1807, 1460, 2371, 2338, 2333, 308, 108, 2851, 870, 854, 1510, 2535,
        1278, 1530, 1185, 1659, 1187, 3109, 874, 1335, 2111, 136, 1215, 2945, 1465,
        1285, 2007, 2719, 2726, 2232, 2512, 75, 156, 3000, 2911, 2980, 872, 2685,
        1590, 2210, 602, 1846, 777, 147, 2170, 2551, 246, 1676, 1755, 460, 291, 235,
        3152, 2742, 2907, 3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103, 1275, 2652,
        1065, 2881, 725, 1508, 2368, 398, 951, 247, 1421, 3222, 2499, 271, 90, 853,
        1860, 3203, 1162, 1618, 666, 320, 8, 2813, 1544, 282, 1838, 1293, 2314, 552,
        2677, 2106, 1571, 205, 2918, 1542, 2721, 2597, 2312, 681, 130, 1602, 1871,
        829, 2946, 3065, 1325, 2756, 1861, 1474, 1202, 2367, 3147, 1752, 2707, 171,
        3127, 3042, 1907, 1836, 1517, 359, 758, 1441];


    public static paramsN = 256;
    public static paramsQ = 3329;
    public static paramsQinv = 62209;
    public static paramsSymBytes = 32;
    public static paramsPolyBytes = 384;
    public static paramsETAK512 = 3;
    public static paramsETAK768K1024 = 2;
    public static paramsPolyvecBytesK512 = 2 * KyberService.paramsPolyBytes;
    public static paramsPolyvecBytesK768 = 3 * KyberService.paramsPolyBytes;
    public static paramsPolyvecBytesK1024 = 4 * KyberService.paramsPolyBytes;
    public static paramsPolyCompressedBytesK512 = 128;
    public static paramsPolyCompressedBytesK768 = 128;
    public static paramsPolyCompressedBytesK1024 = 160;
    public static paramsPolyvecCompressedBytesK512 = 2 * 320;
    public static paramsPolyvecCompressedBytesK768 = 3 * 320;
    public static paramsPolyvecCompressedBytesK1024 = 4 * 352;
    public static paramsIndcpaPublicKeyBytesK512 = KyberService.paramsPolyvecBytesK512 + KyberService.paramsSymBytes;
    public static paramsIndcpaPublicKeyBytesK768 = KyberService.paramsPolyvecBytesK768 + KyberService.paramsSymBytes;
    public static paramsIndcpaPublicKeyBytesK1024 = KyberService.paramsPolyvecBytesK1024 + KyberService.paramsSymBytes;
    public static paramsIndcpaSecretKeyBytesK512 = 2 * KyberService.paramsPolyBytes;
    public static paramsIndcpaSecretKeyBytesK768 = 3 * KyberService.paramsPolyBytes;
    public static paramsIndcpaSecretKeyBytesK1024 = 4 * KyberService.paramsPolyBytes;

// Kyber512SKBytes is a constant representing the byte length of private keys in Kyber-512
    public static Kyber512SKBytes = KyberService.paramsPolyvecBytesK512 + ((KyberService.paramsPolyvecBytesK512 + KyberService.paramsSymBytes) + 2 * KyberService.paramsSymBytes);

// Kyber768SKBytes is a constant representing the byte length of private keys in Kyber-768
    public static Kyber768SKBytes = KyberService.paramsPolyvecBytesK768 + ((KyberService.paramsPolyvecBytesK768 + KyberService.paramsSymBytes) + 2 * KyberService.paramsSymBytes);

// Kyber1024SKBytes is a constant representing the byte length of private keys in Kyber-1024
    public static Kyber1024SKBytes = KyberService.paramsPolyvecBytesK1024 + ((KyberService.paramsPolyvecBytesK1024 + KyberService.paramsSymBytes) + 2 * KyberService.paramsSymBytes);

// Kyber512PKBytes is a constant representing the byte length of public keys in Kyber-512
    public static Kyber512PKBytes = KyberService.paramsPolyvecBytesK512 + KyberService.paramsSymBytes;

// Kyber768PKBytes is a constant representing the byte length of public keys in Kyber-768
    public static Kyber768PKBytes = KyberService.paramsPolyvecBytesK768 + KyberService.paramsSymBytes;

// Kyber1024PKBytes is a constant representing the byte length of public keys in Kyber-1024
    public static Kyber1024PKBytes = KyberService.paramsPolyvecBytesK1024 + KyberService.paramsSymBytes;

// KyberEncoded512PKBytes is a constant representing the byte length of encoded public keys in Kyber-512
    public static KyberEncoded512PKBytes = 967;

// KyberEncoded768PKBytes is a constant representing the byte length of encoded public keys in Kyber-768
    public static KyberEncoded768PKBytes = 1351;

// KyberEncoded1024PKBytes is a constant representing the byte length of encoded public keys in Kyber-1024
    public static KyberEncoded1024PKBytes = 1735;

// Kyber512CTBytes is a constant representing the byte length of ciphertexts in Kyber-512
    public static Kyber512CTBytes = KyberService.paramsPolyvecCompressedBytesK512 + KyberService.paramsPolyCompressedBytesK512;

// Kyber768CTBytes is a constant representing the byte length of ciphertexts in Kyber-768
    public static Kyber768CTBytes = KyberService.paramsPolyvecCompressedBytesK768 + KyberService.paramsPolyCompressedBytesK768;

// Kyber1024CTBytes is a constant representing the byte length of ciphertexts in Kyber-1024
    public static Kyber1024CTBytes = KyberService.paramsPolyvecCompressedBytesK1024 + KyberService.paramsPolyCompressedBytesK1024;

// KyberEncoded512CTBytes is a constant representing the byte length of Encoded ciphertexts in Kyber-512
    public static KyberEncoded512CTBytes = 935;

// KyberEncoded768CTBytes is a constant representing the byte length of Encoded ciphertexts in Kyber-768
    public static KyberEncoded768CTBytes = 1255;

// KyberEncoded1024CTBytes is a constant representing the byte length of Encoded ciphertexts in Kyber-1024
    public static KyberEncoded1024CTBytes = 1735;

// KyberSSBytes is a constant representing the byte length of shared secrets in Kyber
    public static KyberSSBytes = 32;

// KyberEncodedSSBytes is a constant representing the byte length of encoded shared secrets in Kyber
    public static KyberEncodedSSBytes = 193;

    /**
     * Default constructor that is called by the implementing Kyber service
     * @param paramsK
     */
    constructor(public paramsK: number) {
        this.indcpa = new Indcpa(this.paramsK);
    }

    /**
     * Return a string representation of the Kyber algorithm type
     */
    public abstract getAlgorithm(): string;

    /**
     * Generate local Kyber Keys
     */
    public generateKyberKeys(): number[][] {
        // IND-CPA keypair
        const indcpakeys = this.indcpa.indcpaKeyGen();

        const pk = indcpakeys[0];
        const sk = indcpakeys[1];

        // FO transform to make IND-CCA2

        // get hash of pk
        const buffer1 = Buffer.from(pk);
        const hash1 = new SHA3(256);

        hash1.update(buffer1);
        let pkh = hash1.digest();

        // read 32 random values (0-255) into a 32 byte array
        const rnd = Buffer.alloc(KyberService.paramsSymBytes);
        for (let i = 0; i < KyberService.paramsSymBytes; i++) {
            rnd[i] = Utilities.nextInt(256);
        }

        // concatenate to form IND-CCA2 private key: sk + pk + h(pk) + rnd
        for (let i = 0; i < pk.length; i++) {
            sk.push(pk[i]);
        }
        for (let i = 0; i < pkh.length; i++) {
            sk.push(pkh[i]);
        }
        for (let i = 0; i < rnd.length; i++) {
            sk.push(rnd[i]);
        }

        const keys: number[][] = []; // 2
        keys[0] = pk;
        keys[1] = sk;
        return keys;
    }

    /**
     * Generate a shared secret and cipher text from the given
     * public key
     * @param publicKey
     */
    public encrypt(publicKey: number[]): number[][] {

        // random 32 bytes
        const m = Buffer.alloc(KyberService.paramsSymBytes);
        for (let i = 0; i < KyberService.paramsSymBytes; i++) {
            m[i] = Utilities.nextInt(256);
        }

        // hash m with SHA3-256
        const buffer1 = Buffer.from(m);
        const hash1 = new SHA3(256);
        hash1.update(buffer1);
        const mhBuf = hash1.digest();
        const mh: number[] = [];
        for (const val of mhBuf) {
            mh.push(val);
        }

        // hash pk with SHA3-256
        const buffer2 = Buffer.from(publicKey);
        const hash2 = new SHA3(256);
        hash2.update(buffer2);
        let pkh = hash2.digest();

        // hash mh and pkh with SHA3-512
        const buffer3 = Buffer.from(mh);
        const buffer4 = Buffer.from(pkh);
        const hash3 = new SHA3(512);
        hash3.update(buffer3).update(buffer4);
        const kr = hash3.digest();
        const kr1 = kr.slice(0, KyberService.paramsSymBytes);
        const kr2Buf = kr.slice(KyberService.paramsSymBytes, kr.length);

        const kr2: number[] = [];
        for (const num of kr2Buf) {
            kr2.push(num);
        }

        // generate ciphertext c
        const cipherText = this.indcpa.indcpaEncrypt(publicKey, mh, kr2);

        // hash ciphertext with SHA3-256
        const buffer5 = Buffer.from(cipherText);
        const hash4 = new SHA3(256);
        hash4.update(buffer5);
        let ch = hash4.digest();

        // hash kr1 and ch with SHAKE-256
        const buffer6 = Buffer.from(kr1);
        const buffer7 = Buffer.from(ch);
        const hash5 = new SHAKE(256);
        hash5.update(buffer6).update(buffer7);
        const ssBuf = hash5.digest();

        // output (c, ss)
        const result: number[][] = []; // 2
        result[0] = cipherText;
        const sharedSecret: number[] = [];
        for (let i = 0; i < KyberService.paramsSymBytes; ++i) {
            sharedSecret[i] = ssBuf[i];
        }
        result[1] = sharedSecret;

        return result;
    }

    /**
     * Decrypt the given cipher text to create the same shared secret with
     * the local private key
     * @param cipherText
     * @param privateKey
     */
    public decrypt(cipherText: number[], privateKey: number[]): number[] {
        // extract sk, pk, pkh and z
        let startIndex = 0;
        let endIndex = 0;
        switch (this.paramsK) {
            case 2:
                endIndex = KyberService.paramsIndcpaSecretKeyBytesK512;
                break;
            case 3:
                endIndex = KyberService.paramsIndcpaSecretKeyBytesK768;
                break;
            default:
                endIndex = KyberService.paramsIndcpaSecretKeyBytesK1024;
        }

        const indcpaPrivateKey = privateKey.slice(startIndex, endIndex); // indcpa secret key
        startIndex = endIndex;
        switch (this.paramsK) {
            case 2:
                endIndex += KyberService.paramsIndcpaPublicKeyBytesK512;
                break;
            case 3:
                endIndex += KyberService.paramsIndcpaPublicKeyBytesK768;
                break;
            default:
                endIndex += KyberService.paramsIndcpaPublicKeyBytesK1024;
        }
        const indcpaPublicKey = privateKey.slice(startIndex, endIndex); // indcpa public key
        startIndex = endIndex;
        endIndex += KyberService.paramsSymBytes;
        const pkh = privateKey.slice(startIndex, endIndex); // sha3-256 hash
        startIndex = endIndex;
        endIndex += KyberService.paramsSymBytes;
        const z = privateKey.slice(startIndex, endIndex);
        // IND-CPA decrypt
        const m = this.indcpa.indcpaDecrypt(cipherText, indcpaPrivateKey);
        // hash m and pkh with SHA3-512
        const buffer1 = Buffer.from(m);
        const buffer2 = Buffer.from(pkh);
        const hash1 = new SHA3(512);
        hash1.update(buffer1).update(buffer2);
        const krBuf = hash1.digest();
        const kr: number[] = [];
        for (const num of krBuf) {
            kr.push(num);
        }
        const kr1 = krBuf.slice(0, KyberService.paramsSymBytes);
        const kr2Buf = krBuf.slice(KyberService.paramsSymBytes, kr.length);
        const kr2: number[] = [];
        for (const num of kr2Buf) {
            kr2.push(num);
        }
        // IND-CPA encrypt
        const cmp = this.indcpa.indcpaEncrypt(indcpaPublicKey, m, kr2);
        // compare c and cmp to verify the generated shared secret
        const fail = Utilities.constantTimeCompare(cipherText, cmp);
        // hash c with SHA3-256
        const md = new SHA3(256);
        md.update(Buffer.from(cipherText));
        const krh = md.digest();
        let kyberSKBytes = 0;
        switch (this.paramsK) {
            case 2:
                kyberSKBytes = KyberService.Kyber512SKBytes;
                break;
            case 3:
                kyberSKBytes = KyberService.Kyber768SKBytes;
                break;
            default:
                kyberSKBytes = KyberService.Kyber1024SKBytes;
        }

        for (let i = 0; i < KyberService.paramsSymBytes; i++) {
            const length = kyberSKBytes - KyberService.paramsSymBytes + i;
            let skx = privateKey.slice(0, length);
            kr[i] = Utilities.intToByte((kr[i]) ^ ((fail & 0xFF) & ((kr[i]) ^ (skx[i]))));
        }
        const tempBuf: number[] = [];
        let ctr = 0;
        for (ctr = 0; ctr < kr.length; ++ctr) {
            tempBuf[ctr] = kr[ctr];
        }
        let ctr2 = 0;
        for (; ctr < krh.length; ++ctr) {
            tempBuf[ctr] = krh[ctr2++];
        }
        const buffer3 = Buffer.from(cipherText);
        const hash2 = new SHA3(256);
        hash2.update(buffer3);
        let ch = hash2.digest();
        const buffer4 = Buffer.from(kr1);
        const buffer5 = Buffer.from(ch);
        const hash3 = new SHAKE(256);
        hash3.update(buffer4).update(buffer5);
        const ssBuf = hash3.digest();
        const sharedSecret: number[] = [];
        for (let i = 0; i < KyberService.paramsSymBytes; ++i) {
            sharedSecret[i] = ssBuf[i];
        }
        return sharedSecret;
    }
}