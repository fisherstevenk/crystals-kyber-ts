import {Buffer} from "buffer";
import {Utilities} from "./utilities";
import {SHA3, SHAKE} from "sha3";
import {Poly} from "./poly";
import {KyberService} from "../services/kyber.service";

export class Indcpa {
    public poly: Poly;

    constructor(public paramsK: number) {
        this.poly = new Poly(this.paramsK);
    }

    /**
     * Generates public and private keys for the CPA-secure public-key
     * encryption scheme underlying Kyber.
     */
    public indcpaKeyGen() {
        // random bytes for seed
        const rnd = Buffer.alloc(KyberService.paramsSymBytes);
        for (let i = 0; i < KyberService.paramsSymBytes; i++) {
            rnd[i] = Utilities.nextInt(256);
        }

        // hash rnd with SHA3-512
        const buffer1 = Buffer.from(rnd);
        const hash1 = new SHA3(512);
        hash1.update(buffer1);
        const seed = hash1.digest();
        const publicSeedBuf = seed.slice(0, KyberService.paramsSymBytes);
        const noiseSeedBuf = seed.slice(KyberService.paramsSymBytes, (KyberService.paramsSymBytes * 2));
        const publicSeed: number[] = [];
        const noiseSeed: number[] = [];
        for (const num of publicSeedBuf) {
            publicSeed.push(num);
        }
        for (const num of noiseSeedBuf) {
            noiseSeed.push(num);
        }
        // generate public matrix A (already in NTT form)
        const a = this.generateMatrix(publicSeed, false);
        const s: number[][] = []; //this.paramsK
        const e: number[][] = []; // this.paramsK
        for (let i = 0; i < this.paramsK; i++) {
            s[i] = this.poly.getNoisePoly(noiseSeed, i, this.paramsK);
            e[i] = this.poly.getNoisePoly(noiseSeed, (i + this.paramsK), this.paramsK);
        }
        for (let i = 0; i < this.paramsK; i++) {
            s[i] = this.poly.ntt(s[i]);
        }

        for (let i = 0; i < this.paramsK; i++) {
            e[i] = this.poly.ntt(e[i]);
        }

        for (let i = 0; i < this.paramsK; i++) {
            s[i] = this.poly.polyReduce(s[i]);
        }
        const pk: number[][] = []; // this.paramsK
        for (let i = 0; i < this.paramsK; i++) {
            pk[i] = this.poly.polyToMont(this.poly.polyVectorPointWiseAccMont(a[i], s));
        }

        for (let i = 0; i < this.paramsK; i++) {
            pk[i] = this.poly.polyAdd(pk[i], e[i]);
        }

        for (let i = 0; i < this.paramsK; i++) {
            pk[i] = this.poly.polyReduce(pk[i]);
        }

        // ENCODE KEYS
        const keys: number[][] = []; // 2

        // PUBLIC KEY
        // turn polynomials into byte arrays
        keys[0] = [];
        let bytes = [];
        for (let i = 0; i < this.paramsK; i++) {
            bytes = this.poly.polyToBytes(pk[i]);
            for (let j = 0; j < bytes.length; j++) {
                keys[0].push(bytes[j]);
            }
        }
        // append public seed
        for (let i = 0; i < publicSeed.length; i++) {
            keys[0].push(publicSeed[i]);
        }

        // PRIVATE KEY
        keys[1] = [];
        bytes = [];
        for (let i = 0; i < this.paramsK; i++) {
            bytes = this.poly.polyToBytes(s[i]);
            for (let j = 0; j < bytes.length; j++) {
                keys[1].push(bytes[j]);
            }
        }
        return keys;
    }

    /**
     * Encrypt the given message using the Kyber public-key encryption scheme
     *
     * @param publicKey
     * @param msg
     * @param coins
     * @return
     */
    public indcpaEncrypt(publicKey: number[], msg: number[], coins: number[]): number[] {
        const pk: number[][] = [];
        let start;
        let end;
        // decode message m
        let k = this.poly.polyFromData(msg);
        for (let i = 0; i < this.paramsK; i++) {
            start = (i * KyberService.paramsPolyBytes);
            end = (i + 1) * KyberService.paramsPolyBytes;
            pk[i] = this.poly.polyFromBytes(publicKey.slice(start, end));
        }
        let seed;
        switch (this.paramsK) {
            case 2:
                seed = publicKey.slice(KyberService.paramsPolyvecBytesK512, KyberService.paramsIndcpaPublicKeyBytesK512);
                break;
            case 3:
                seed = publicKey.slice(KyberService.paramsPolyvecBytesK768, KyberService.paramsIndcpaPublicKeyBytesK768);
                break;
            default:
                seed = publicKey.slice(KyberService.paramsPolyvecBytesK1024, KyberService.paramsIndcpaPublicKeyBytesK1024);
        }
        const at = this.generateMatrix(seed, true);
        const sp: number[][] = []; // this.paramsK
        const ep: number[][] = []; // this.paramsK
        for (let i = 0; i < this.paramsK; i++) {
            sp[i] = this.poly.getNoisePoly(coins, i, this.paramsK);
            ep[i] = this.poly.getNoisePoly(coins, i + this.paramsK, 3);
        }
        let epp: number[] = this.poly.getNoisePoly(coins, (this.paramsK * 2), 3);

        for (let i = 0; i < this.paramsK; i++) {
            sp[i] = this.poly.ntt(sp[i]);
        }
        for (let i = 0; i < this.paramsK; i++) {
            sp[i] = this.poly.polyReduce(sp[i]);
        }

        let bp: number[][] = []; // this.paramsK
        for (let i = 0; i < this.paramsK; i++) {
            bp[i] = this.poly.polyVectorPointWiseAccMont(at[i], sp);
        }
        let v = this.poly.polyVectorPointWiseAccMont(pk, sp);
        bp = this.poly.polyVectorInvNTTMont(bp);
        v = this.poly.invNTT(v);
        bp = this.poly.polyVectorAdd(bp, ep);
        v = this.poly.polyAdd(v, epp);
        v = this.poly.polyAdd(v, k);
        bp = this.poly.polyVectorReduce(bp);
        v = this.poly.polyReduce(v);
        const bCompress = this.poly.compressPolyVector(bp);
        const vCompress = this.poly.compressPoly(v);
        const c3: number[] = [];
        for (let i = 0; i < bCompress.length; ++i) {
            c3[i] = bCompress[i];
        }
        for (let i = 0; i < vCompress.length; ++i) {
            c3[i + bCompress.length] = vCompress[i];
        }
        return c3;
    }

    /**
     * Decrypt the given byte array using the Kyber public-key encryption scheme
     *
     * @param packedCipherText
     * @param privateKey
     * @return
     */
    public indcpaDecrypt(packedCipherText: number[], privateKey: number[]): number[] {
        let bpEndIndex: number;
        let vEndIndex: number;
        switch (this.paramsK) {
            case 2:
                bpEndIndex = KyberService.paramsPolyvecCompressedBytesK512;
                vEndIndex = bpEndIndex + KyberService.paramsPolyCompressedBytesK512;
                break;
            case 3:
                bpEndIndex = KyberService.paramsPolyvecCompressedBytesK768;
                vEndIndex = bpEndIndex + KyberService.paramsPolyCompressedBytesK768;
                break;
            default:
                bpEndIndex = KyberService.paramsPolyvecCompressedBytesK1024;
                vEndIndex = bpEndIndex + KyberService.paramsPolyCompressedBytesK1024;
        }

        let bp = this.poly.decompressPolyVector(packedCipherText.slice(0, bpEndIndex));
        const v = this.poly.decompressPoly(packedCipherText.slice(bpEndIndex, vEndIndex));

        const privateKeyPolyvec = this.poly.polyVectorFromBytes(privateKey);
        bp = this.poly.polyVectorNTT(bp);

        let mp = this.poly.polyVectorPointWiseAccMont(privateKeyPolyvec, bp);

        mp = this.poly.invNTT(mp);
        mp = this.poly.subtract(v, mp);
        mp = this.poly.polyReduce(mp);
        return this.poly.polyToMsg(mp);
    }

    /**
     * Generate a polynomial vector matrix from the given seed
     *
     * @param seed
     * @param transposed
     * @return
     */
    public generateMatrix(seed: number[], transposed: boolean): number[][][] {
        let a: number[][][] = []; //this.paramsK)
        const xof = new SHAKE(128);
        let ctr = 0;
        for (let i = 0; i < this.paramsK; i++) {
            a[i] = []; // this.paramsK
            let transpose: number[] = []; // 2
            for (let j = 0; j < this.paramsK; j++) {
                // set if transposed matrix or not
                transpose[0] = j;
                transpose[1] = i;
                if (transposed) {
                    transpose[0] = i;
                    transpose[1] = j;
                }
                // obtain xof of (seed+i+j) or (seed+j+i) depending on above code
                // output is 672 bytes in length
                xof.reset();
                const buffer1 = Buffer.from(seed);
                const buffer2 = Buffer.from(transpose);
                xof.update(buffer1).update(buffer2);
                let outputString = xof.digest({format: "binary", buffer: Buffer.alloc(672)});
                let output = Buffer.alloc(outputString.length);
                output.fill(outputString);
                // run rejection sampling on the output from above
                let outputlen = 3 * 168; // 504
                let result: any[] = []; // 2
                result = this.generateUniform(output.slice(0, 504), outputlen, KyberService.paramsN);
                a[i][j] = result[0]; // the result here is an NTT-representation
                ctr = result[1]; // keeps track of index of output array from sampling function
                while (ctr < KyberService.paramsN) { // if the polynomial hasnt been filled yet with mod q entries
                    const outputn = output.slice(504, 672); // take last 168 bytes of byte array from xof
                    let result1: any[] = []; //2
                    result1 = this.generateUniform(outputn, 168, KyberService.paramsN - ctr); // run sampling function again
                    let missing = result1[0]; // here is additional mod q polynomial coefficients
                    let ctrn = result1[1]; // how many coefficients were accepted and are in the output
                    // starting at last position of output array from first sampling function until 256 is reached
                    for (let k = ctr; k < KyberService.paramsN; k++) {
                        a[i][j][k] = missing[k - ctr]; // fill rest of array with the additional coefficients until full
                    }
                    ctr = ctr + ctrn; // update index
                }

            }
        }
        return a;
    }

    /**
     * Runs rejection sampling on uniform random bytes to generate uniform
     * random integers modulo `Q`
     *
     * @param buf
     * @param bufl
     * @param len
     * @return
     */
    public generateUniform(buf: Buffer, bufl: number, len: number): number[][] {
        let uniformR: number[] = [];
        for (let i = 0; i < KyberService.paramsPolyBytes; ++i) {
            uniformR[i] = 0;
        }
        let d1, d2;
        let j = 0;
        let uniformI = 0;

        while ((uniformI < len) && ((j + 3) <= bufl)) {
            // compute d1 and d2
            d1 = (Utilities.uint16((buf[j]) >> 0) | (Utilities.uint16(buf[j + 1]) << 8)) & 0xFFF;
            d2 = (Utilities.uint16((buf[j + 1]) >> 4) | (Utilities.uint16(buf[j + 2]) << 4)) & 0xFFF;
            // increment input buffer index by 3
            j = j + 3;

            // if d1 is less than 3329
            if (d1 < KyberService.paramsQ) {
                // assign to d1
                uniformR[uniformI] = d1;
                // increment position of output array
                ++uniformI;
            }
            if (uniformI < len && d2 < KyberService.paramsQ) {
                uniformR[uniformI] = d2;
                ++uniformI;
            }
        }

        let result: any[] = []; // 2
        result[0] = uniformR; // returns polynomial NTT representation
        result[1] = uniformI; // ideally should return 256
        return result;
    }
}