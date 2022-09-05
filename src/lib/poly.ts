import {Utilities} from "./utilities";
import {Buffer} from "buffer";
import {SHAKE} from "sha3";
import {ByteOps} from "./byte-ops";
import {KyberService} from "../services/kyber.service";

export class Poly {
    public byteOps: ByteOps;

    constructor(public paramsK: number) {
        this.byteOps = new ByteOps(this.paramsK);
    }

    /**
     * Applies the inverse number-theoretic transform (NTT) to all elements of a
     * vector of polynomials and multiplies by Montgomery factor 2^16
     * @param r
     */
    public polyVectorInvNTTMont(r: number[][]): number[][] {
        for (let i: number = 0; i < this.paramsK; i++) {
            r[i] = this.polyInvNTTMont(r[i]);
        }
        return r;

    }

    /**
     * Applies Barrett reduction to each coefficient of each element of a vector
     * of polynomials.
     *
     * @param r
     * @return
     */
    public polyVectorReduce(r: number[][]): number[][] {
        for (let i = 0; i < this.paramsK; i++) {
            r[i] = this.polyReduce(r[i]);
        }
        return r;
    }

    /**
     * Computes an in-place inverse of a negacyclic number-theoretic transform
     * (NTT) of a polynomial
     *
     * Input is assumed bit-revered order
     *
     * Output is assumed normal order
     *
     * @param r
     * @return
     */
    public polyInvNTTMont(r: number[]): number[] {
        return this.invNTT(r)
    }


    /**
     * Applies forward number-theoretic transforms (NTT) to all elements of a
     * vector of polynomial
     *
     * @param r
     * @return
     */
    public polyVectorNTT(r: number[][]): number[][] {
        for (let i = 0; i < this.paramsK; i++) {
            r[i] = this.ntt(r[i]);
        }
        return r;
    }


    /**
     * Deserialize a byte array into a polynomial vector
     *
     * @param a
     * @return
     */
    public polyVectorFromBytes(a: number[]): number[][] {
        let r: number[][] = [];
        let start;
        let end;
        for (let i = 0; i < this.paramsK; i++) {
            start = (i * KyberService.paramsPolyBytes);
            end = (i + 1) * KyberService.paramsPolyBytes;
            r[i] = this.polyFromBytes(a.slice(start, end));
        }
        return r;
    }

    /**
     * Serialize a polynomial in to an array of bytes
     *
     * @param a
     * @return
     */
    public polyToBytes(a: Array<number>) {
        let t0, t1;
        let r: number[] = [];
        let a2 = this.polyConditionalSubQ(a);
        for (let i = 0; i < KyberService.paramsN / 2; i++) {
            t0 = Utilities.uint16(a2[2 * i]);
            t1 = Utilities.uint16(a2[2 * i + 1]);
            r[3 * i + 0] = Utilities.byte(t0 >> 0);
            r[3 * i + 1] = Utilities.byte(t0 >> 8) | Utilities.byte(t1 << 4);
            r[3 * i + 2] = Utilities.byte(t1 >> 4);
        }
        return r;
    }

    /**
     * Check the 0xFFF
     * @param a
     */
    public polyFromBytes(a: number[]) {
        let r: number[] = [];
        for (let i = 0; i < KyberService.paramsPolyBytes; i++) {
            r[i] = 0;
        }
        for (let i = 0; i < KyberService.paramsN / 2; i++) {
            r[2 * i] = Utilities.int16(((Utilities.uint16(a[3 * i + 0]) >> 0) | (Utilities.uint16(a[3 * i + 1]) << 8)) & 0xFFF);
            r[2 * i + 1] = Utilities.int16(((Utilities.uint16(a[3 * i + 1]) >> 4) | (Utilities.uint16(a[3 * i + 2]) << 4)) & 0xFFF);
        }
        return r;
    }

    /**
     * Convert a polynomial to a 32-byte message
     *
     * @param a
     * @return
     */
    public polyToMsg(a: Array<number>): number[] {
        const msg: number[] = []; // 32
        let t;
        const a2 = this.polyConditionalSubQ(a);
        for (let i = 0; i < KyberService.paramsN / 8; i++) {
            msg[i] = 0;
            for (let j = 0; j < 8; j++) {
                t = (((Utilities.uint16(a2[8 * i + j]) << 1) + Utilities.uint16(KyberService.paramsQ / 2)) / Utilities.uint16(KyberService.paramsQ)) & 1;
                msg[i] |= Utilities.byte(t << j);
            }
        }
        return msg;
    }

    /**
     * Convert a 32-byte message to a polynomial
     *
     * @param msg
     * @return
     */
    public polyFromData(msg: number[]) {
        let r: number[] = [];
        for (let i = 0; i < KyberService.paramsPolyBytes; ++i) {
            r[i] = 0;
        }
        let mask;
        for (let i = 0; i < KyberService.paramsN / 8; i++) {
            for (let j = 0; j < 8; j++) {
                mask = -1 * Utilities.int16((msg[i] >> j) & 1);
                r[8 * i + j] = mask & Utilities.int16((KyberService.paramsQ + 1) / 2);
            }
        }
        return r;
    }

    /**
     * Generate a deterministic noise polynomial from a seed and nonce
     *
     * The polynomial output will be close to a centered binomial distribution
     *
     * @param seed
     * @param nonce
     * @param paramsK
     * @return
     */
    public getNoisePoly(seed: number[], nonce: number, paramsK: number) {
        let l;
        switch (paramsK) {
            case 2:
                l = KyberService.paramsETAK512 * KyberService.paramsN / 4;
                break;
            default:
                l = KyberService.paramsETAK768K1024 * KyberService.paramsN / 4;
        }
        let p = this.generatePRFByteArray(l, seed, nonce);
        return this.byteOps.generateCBDPoly(p, paramsK);
    }

    /**
     * Pseudo-random function to derive a deterministic array of random bytes
     * from the supplied secret key object and other parameters.
     *
     * @param l
     * @param key
     * @param nonce
     * @return
     */
    public generatePRFByteArray(l: number, key: number[], nonce: number): Buffer {
        const nonce_arr: number[] = []; // 1
        nonce_arr[0] = nonce;
        const hash = new SHAKE(256);
        hash.reset();
        const buffer1 = Buffer.from(key);
        const buffer2 = Buffer.from(nonce_arr);
        hash.update(buffer1).update(buffer2);
        const bufString = hash.digest({format: "binary", buffer: Buffer.alloc(l)}); // 128 long byte array
        const buf = Buffer.alloc(bufString.length);
        for (let i = 0; i < bufString.length; ++i) {
            buf[i] = +bufString[i];
        }
        return buf;
    }

    /**
     * Perform an in-place number-theoretic transform (NTT)
     *
     * Input is in standard order
     *
     * Output is in bit-reversed order
     *
     * @param r
     * @return
     */
    public ntt(r: number[]): number[] {
        let j = 0;
        let k = 1;
        let zeta;
        let t;
        for (let l = 128; l >= 2; l >>= 1) {
            // 0,
            for (let start = 0; start < 256; start = j + l) {
                zeta = KyberService.nttZetas[k];
                k++;
                for (j = start; j < start + l; j++) {
                    t = this.byteOps.modQMulMont(zeta, r[j + l]); // t is mod q
                    r[j + l] = Utilities.int16(r[j] - t);
                    r[j] = Utilities.int16(r[j] + t);
                }
            }
        }
        return r;
    }

    /**
     * Apply Barrett reduction to all coefficients of this polynomial
     *
     * @param r
     * @return
     */
    public polyReduce(r: Array<number>) {
        for (let i = 0; i < KyberService.paramsN; i++) {
            r[i] = this.byteOps.barrettReduce(r[i]);
        }
        return r;
    }

    /**
     * Performs an in-place conversion of all coefficients of a polynomial from
     * the normal domain to the Montgomery domain
     *
     * @param polyR
     * @return
     */
    public polyToMont(r: Array<number>) {
        for (let i = 0; i < KyberService.paramsN; i++) {
            r[i] = this.byteOps.byteopsMontgomeryReduce(Utilities.int32(r[i]) * Utilities.int32(1353));
        }
        return r;
    }

    /**
     * Pointwise-multiplies elements of the given polynomial-vectors ,
     * accumulates the results , and then multiplies by 2^-16
     *
     * @param a
     * @param b
     * @return
     */
    public polyVectorPointWiseAccMont(a: number[][], b: number[][]) {
        let r = this.polyBaseMulMont(a[0], b[0]);
        let t;
        for (let i = 1; i < this.paramsK; i++) {
            t = this.polyBaseMulMont(a[i], b[i]);
            r = this.polyAdd(r, t);
        }
        return this.polyReduce(r);
    }

    /**
     * Multiply two polynomials in the number-theoretic transform (NTT) domain
     *
     * @param a
     * @param b
     * @return
     */
    public polyBaseMulMont(a: number[], b: number[]): number[] {
        let rx, ry;
        for (let i = 0; i < KyberService.paramsN / 4; i++) {
            rx = this.nttBaseMuliplier(
                a[4 * i + 0], a[4 * i + 1],
                b[4 * i + 0], b[4 * i + 1],
                KyberService.nttZetas[64 + i]
            );
            ry = this.nttBaseMuliplier(
                a[4 * i + 2], a[4 * i + 3],
                b[4 * i + 2], b[4 * i + 3],
                -KyberService.nttZetas[64 + i]
            );

            a[4 * i + 0] = rx[0];
            a[4 * i + 1] = rx[1];
            a[4 * i + 2] = ry[0];
            a[4 * i + 3] = ry[1];
        }
        return a;
    }

    /**
     * Performs the multiplication of polynomials
     *
     * @param a0
     * @param a1
     * @param b0
     * @param b1
     * @param zeta
     * @return
     */
    public nttBaseMuliplier(a0: number, a1: number, b0: number, b1: number, zeta: number) {
        let r: number[] = []; // 2
        r[0] = this.byteOps.modQMulMont(a1, b1);
        r[0] = this.byteOps.modQMulMont(r[0], zeta);
        r[0] = r[0] + this.byteOps.modQMulMont(a0, b0);
        r[1] = this.byteOps.modQMulMont(a0, b1);
        r[1] = r[1] + this.byteOps.modQMulMont(a1, b0);
        return r;
    }

    /**
     * Add two polynomial vectors
     *
     * @param a
     * @param b
     * @return
     */
    public polyVectorAdd(a: number[][], b: number[][]) {
        for (let i = 0; i < this.paramsK; i++) {
            a[i] = this.polyAdd(a[i], b[i]);
        }
        return a;
    }

    /**
     * Add two polynomials
     *
     * @param a
     * @param b
     * @return
     */
    public polyAdd(a: Array<number>, b: Array<number>) {
        let c: number[] = [];
        // needs to be 384
        for (let i = 0; i < a.length; ++i) {
            c[i] = 0;
        }
        for (let i = 0; i < KyberService.paramsN; i++) {
            c[i] = a[i] + b[i];
        }
        return c;
    }

    /**
     * Subtract two polynomials
     *
     * @param a
     * @param b
     * @return
     */
    public subtract(a: Array<number>, b: Array<number>) {
        for (let i = 0; i < KyberService.paramsN; i++) {
            a[i] = a[i] - b[i];
        }
        return a;
    }

    /**
     * Perform an in-place inverse number-theoretic transform (NTT)
     *
     * Input is in bit-reversed order
     *
     * Output is in standard order
     *
     * @param r
     * @return
     */
    public invNTT(r: Array<number>) {
        let j = 0;
        let k = 0;
        let zeta;
        let t;
        for (let l = 2; l <= 128; l <<= 1) {
            for (let start = 0; start < 256; start = j + l) {
                zeta = KyberService.nttZetasInv[k];
                k = k + 1;
                for (j = start; j < start + l; j++) {
                    t = r[j];
                    r[j] = this.byteOps.barrettReduce(t + r[j + l]);
                    r[j + l] = t - r[j + l];
                    r[j + l] = this.byteOps.modQMulMont(zeta, r[j + l]);
                }
            }
        }
        for (j = 0; j < 256; j++) {
            r[j] = this.byteOps.modQMulMont(r[j], KyberService.nttZetasInv[127]);
        }
        return r;
    }

    /**
     * Perform a lossly compression and serialization of a vector of polynomials
     *
     * @param a
     * @param paramsK
     * @return
     */
    public compressPolyVector(a: number[][]): number[] {
        a = this.polyVectorCSubQ(a);
        let rr = 0;
        let r: number[] = [];
        let t: number[] = [];

        switch (this.paramsK) {
            case 2:
            case 3:
                for (let i = 0; i < this.paramsK; i++) {
                    for (let j = 0; j < KyberService.paramsN / 4; j++) {
                        for (let k = 0; k < 4; k++) {
                            t[k] = (((a[i][4 * j + k] << 10) + KyberService.paramsQ / 2) / KyberService.paramsQ) & 0b1111111111;
                        }
                        r[rr + 0] = Utilities.byte(t[0] >> 0);
                        r[rr + 1] = Utilities.byte(Utilities.byte(t[0] >> 8) | Utilities.byte(t[1] << 2));
                        r[rr + 2] = Utilities.byte(Utilities.byte(t[1] >> 6) | Utilities.byte(t[2] << 4));
                        r[rr + 3] = Utilities.byte(Utilities.byte(t[2] >> 4) | Utilities.byte(t[3] << 6));
                        r[rr + 4] = Utilities.byte((t[3] >> 2));
                        rr = rr + 5;
                    }
                }
                break;
            default:
                for (let i = 0; i < this.paramsK; i++) {
                    for (let j = 0; j < KyberService.paramsN / 8; j++) {
                        for (let k = 0; k < 8; k++) {
                            t[k] = Utilities.int32((((Utilities.int32(a[i][8 * j + k]) << 11) + Utilities.int32(KyberService.paramsQ / 2)) / Utilities.int32(KyberService.paramsQ)) & 0x7ff);
                        }
                        r[rr + 0] = Utilities.byte((t[0] >> 0));
                        r[rr + 1] = Utilities.byte((t[0] >> 8) | (t[1] << 3));
                        r[rr + 2] = Utilities.byte((t[1] >> 5) | (t[2] << 6));
                        r[rr + 3] = Utilities.byte((t[2] >> 2));
                        r[rr + 4] = Utilities.byte((t[2] >> 10) | (t[3] << 1));
                        r[rr + 5] = Utilities.byte((t[3] >> 7) | (t[4] << 4));
                        r[rr + 6] = Utilities.byte((t[4] >> 4) | (t[5] << 7));
                        r[rr + 7] = Utilities.byte((t[5] >> 1));
                        r[rr + 8] = Utilities.byte((t[5] >> 9) | (t[6] << 2));
                        r[rr + 9] = Utilities.byte((t[6] >> 6) | (t[7] << 5));
                        r[rr + 10] = Utilities.byte((t[7] >> 3));
                        rr = rr + 11;
                    }
                }
        }
        return r;
    }

    /**
     * Performs lossy compression and serialization of a polynomial
     *
     * @param polyA
     * @return
     */
    public compressPoly(polyA: number[]): number[] {
        let rr = 0;
        let r: number[] = [];
        let t: number[] = []; // 8
        const qDiv2 = (KyberService.paramsQ / 2);
        switch (this.paramsK) {
            case 2:
            case 3:
                for (let i = 0; i < KyberService.paramsN / 8; i++) {
                    for (let j = 0; j < 8; j++) {
                        const step1: number = Utilities.int32((polyA[8 * i + j]) << 4);
                        const step2 = Utilities.int32((step1 + qDiv2) / (KyberService.paramsQ));
                        t[j] = Utilities.intToByte(step2 & 15);
                    }
                    r[rr + 0] = Utilities.intToByte(t[0] | (t[1] << 4));
                    r[rr + 1] = Utilities.intToByte(t[2] | (t[3] << 4));
                    r[rr + 2] = Utilities.intToByte(t[4] | (t[5] << 4));
                    r[rr + 3] = Utilities.intToByte(t[6] | (t[7] << 4));
                    rr = rr + 4;
                }
                break;
            default:
                for (let i = 0; i < KyberService.paramsN / 8; i++) {
                    for (let j = 0; j < 8; j++) {
                        const step1: number = Utilities.int32((polyA[(8 * i) + j] << 5));
                        const step2 = Utilities.int32((step1 + qDiv2) / (KyberService.paramsQ));
                        t[j] = Utilities.intToByte(step2 & 31);
                    }
                    r[rr + 0] = Utilities.intToByte((t[0] >> 0) | (t[1] << 5));
                    r[rr + 1] = Utilities.intToByte((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
                    r[rr + 2] = Utilities.intToByte((t[3] >> 1) | (t[4] << 4));
                    r[rr + 3] = Utilities.intToByte((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
                    r[rr + 4] = Utilities.intToByte((t[6] >> 2) | (t[7] << 3));
                    rr = rr + 5;
                }
        }
        return r;
    }

    /**
     * De-serialize and decompress a vector of polynomials
     *
     * Since the compress is lossy, the results will not be exactly the same as
     * the original vector of polynomials
     *
     * @param a
     * @return
     */
    public decompressPolyVector(a: number[]) {
        const r: number[][] = []; // this.paramsK
        for (let i = 0; i < this.paramsK; i++) {
            r[i] = [];
        }
        let aa = 0;
        const t: number[] = []; // 8
        switch (this.paramsK) {
            //TESTED
            case 2:
            case 3:
                let ctr = 0;
                for (let i = 0; i < this.paramsK; i++) {
                    for (let j = 0; j < (KyberService.paramsN / 4); j++) {
                        t[0] = (Utilities.uint16(a[aa + 0]) >> 0) | (Utilities.uint16(a[aa + 1]) << 8);
                        t[1] = (Utilities.uint16(a[aa + 1]) >> 2) | (Utilities.uint16(a[aa + 2]) << 6);
                        t[2] = (Utilities.uint16(a[aa + 2]) >> 4) | (Utilities.uint16(a[aa + 3]) << 4);
                        t[3] = (Utilities.uint16(a[aa + 3]) >> 6) | (Utilities.uint16(a[aa + 4]) << 2);
                        aa = aa + 5;
                        ++ctr;
                        for (let k = 0; k < 4; k++) {
                            r[i][4 * j + k] = (Utilities.uint32(t[k] & 0x3FF) * KyberService.paramsQ + 512) >> 10;
                        }
                    }
                }
                break;
            default:
                for (let i = 0; i < this.paramsK; i++) {
                    for (let j = 0; j < KyberService.paramsN / 8; j++) {
                        t[0] = (Utilities.uint16(a[aa + 0]) >> 0) | (Utilities.uint16(a[aa + 1]) << 8);
                        t[1] = (Utilities.uint16(a[aa + 1]) >> 3) | (Utilities.uint16(a[aa + 2]) << 5);
                        t[2] = (Utilities.uint16(a[aa + 2]) >> 6) | (Utilities.uint16(a[aa + 3]) << 2) | (Utilities.uint16(a[aa + 4]) << 10);
                        t[3] = (Utilities.uint16(a[aa + 4]) >> 1) | (Utilities.uint16(a[aa + 5]) << 7);
                        t[4] = (Utilities.uint16(a[aa + 5]) >> 4) | (Utilities.uint16(a[aa + 6]) << 4);
                        t[5] = (Utilities.uint16(a[aa + 6]) >> 7) | (Utilities.uint16(a[aa + 7]) << 1) | (Utilities.uint16(a[aa + 8]) << 9);
                        t[6] = (Utilities.uint16(a[aa + 8]) >> 2) | (Utilities.uint16(a[aa + 9]) << 6);
                        t[7] = (Utilities.uint16(a[aa + 9]) >> 5) | (Utilities.uint16(a[aa + 10]) << 3);
                        aa = aa + 11;
                        for (let k = 0; k < 8; k++) {
                            r[i][8 * j + k] = (Utilities.uint32(t[k] & 0x7FF) * KyberService.paramsQ + 1024) >> 11;
                        }
                    }
                }
        }
        return r;
    }

    /**
     * Applies the conditional subtraction of Q (KyberParams) to each coefficient of
     * each element of a vector of polynomials.
     */
    public polyVectorCSubQ(r: number[][]): number[][] {
        for (let i = 0; i < this.paramsK; i++) {
            r[i] = this.polyConditionalSubQ(r[i]);
        }
        return r;
    }

    /**
     * Apply the conditional subtraction of Q (KyberParams) to each coefficient of a
     * polynomial
     *
     * @param r
     * @return
     */
    public polyConditionalSubQ(r: Array<number>) {
        for (let i = 0; i < KyberService.paramsN; i++) {
            r[i] = r[i] - KyberService.paramsQ;
            r[i] = r[i] + ((r[i] >> 31) & KyberService.paramsQ);
        }
        return r;
    }

    /**
     * De-serialize and decompress a vector of polynomials
     *
     * Since the compress is lossy, the results will not be exactly the same as
     * the original vector of polynomials
     *
     * @param a
     * @return
     */
    public decompressPoly(a: number[]) {
        let r: number[] = []; // 384
        let t: number[] = []; // 8
        let aa = 0;
        switch (this.paramsK) {
            case 2:
            case 3:
                // TESTED
                for (let i = 0; i < KyberService.paramsN / 2; i++) {
                    r[2 * i + 0] = Utilities.int16((((Utilities.byte(a[aa]) & 15) * Utilities.uint32(KyberService.paramsQ)) + 8) >> 4);
                    r[2 * i + 1] = Utilities.int16((((Utilities.byte(a[aa]) >> 4) * Utilities.uint32(KyberService.paramsQ)) + 8) >> 4);
                    aa = aa + 1;
                }
                break;
            default:
                for (let i = 0; i < KyberService.paramsN / 8; i++) {
                    t[0] = (a[aa + 0] >> 0);
                    t[1] = Utilities.byte(a[aa + 0] >> 5) | Utilities.byte((a[aa + 1] << 3));
                    t[2] = (a[aa + 1] >> 2);
                    t[3] = Utilities.byte((a[aa + 1] >> 7)) | Utilities.byte((a[aa + 2] << 1));
                    t[4] = Utilities.byte((a[aa + 2] >> 4)) | Utilities.byte((a[aa + 3] << 4));
                    t[5] = (a[aa + 3] >> 1);
                    t[6] = Utilities.byte((a[aa + 3] >> 6)) | Utilities.byte((a[aa + 4] << 2));
                    t[7] = (a[aa + 4] >> 3);
                    aa = aa + 5;
                    for (let j = 0; j < 8; j++) {
                        r[8 * i + j] = Utilities.int16(((Utilities.byte(t[j] & 31) * Utilities.uint32(KyberService.paramsQ)) + 16) >> 5);
                    }
                }
        }
        return r;
    }
}