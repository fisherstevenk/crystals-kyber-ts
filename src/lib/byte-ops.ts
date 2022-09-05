import {Buffer} from "buffer";
import {Utilities} from "./utilities";
import {KyberService} from "../services/kyber.service";

/**
 * Utility class for byte operations
 */
export class ByteOps {

    constructor(public paramsK: number) {

    }

    /**
     * Generate a polynomial with coefficients distributed according to a
     * centered binomial distribution with parameter eta, given an array of
     * uniformly random bytes.
     *
     * @param buff
     * @param paramsK
     * @return
     */
    public generateCBDPoly(buff: Buffer, paramsK: number) {
        const buf = Buffer.from(buff);
        let t, d;
        let a, b;
        let r = new Array(KyberService.paramsPolyBytes).fill(0);
        switch (paramsK) {
            case 2:
                for (let i = 0; i < KyberService.paramsN / 4; i++) {
                    t = this.convertByteTo24BitUnsignedInt(buf.slice(3 * i, buf.length));
                    d = t & 0x00249249;
                    d = d + ((t >> 1) & 0x00249249);
                    d = d + ((t >> 2) & 0x00249249);
                    for (let j = 0; j < 4; j++) {
                        a = Utilities.int16((d >> (6 * j + 0)) & 0x7);
                        b = Utilities.int16((d >> (6 * j + KyberService.paramsETAK512)) & 0x7);
                        r[4 * i + j] = a - b;
                    }
                }
                break;
            default:
                for (let i = 0; i < KyberService.paramsN / 8; i++) {
                    t = (this.convertByteTo32BitUnsignedInt(buf.slice(4 * i, buf.length)));
                    d = (t & 0x55555555);
                    d = d + (((t >> 1) & 0x55555555) >>> 0);
                    for (let j = 0; j < 8; j++) {
                        a = Utilities.int16((((d >> (4 * j + 0))) & 0x3));
                        b = Utilities.int16((((d >> (4 * j + KyberService.paramsETAK768K1024))) & 0x3));
                        r[8 * i + j] = a - b;
                    }
                }
        }
        return r;
    }

    /**
     * Returns a 24-bit unsigned integer as a long from byte x
     *
     * @param x
     * @return
     */
    public convertByteTo24BitUnsignedInt(x: any) {
        let r;
        r = Utilities.int32(x[0] & 0xFF);
        r = r | (Utilities.int32(x[1] & 0xFF) << 8);
        r = r | (Utilities.int32(x[2] & 0xFF) << 16);
        return r;
    }

    /**
     * Returns a 24-bit unsigned integer as a long from byte x
     *
     * @param x
     * @return
     */
    public convertByteTo32BitUnsignedInt(x: Buffer) {
        let r;
        r = Utilities.int32(x[0] & 0xFF);
        r = (((r | (Utilities.int32(x[1] & 0xFF) << 8))));
        r = (((r | (Utilities.int32(x[2] & 0xFF) << 16))));
        r = (((r | Utilities.int32(Utilities.int32(x[3] & 0xFF) << 24))));
        //     last one won't print the same as java
        return r;
    }

    /**
     * Computes a Barrett reduction given a 16 Bit Integer
     *
     * @param a
     * @return
     */
    public barrettReduce(a: number) {
        let shift = Utilities.int32(1 << 26);
        let v = +Utilities.int16((shift + (KyberService.paramsQ / 2)) / KyberService.paramsQ).toFixed(0);
        let t = Utilities.int16((v * a) >> 26);
        t = Utilities.int16(t * KyberService.paramsQ);
        return a - t;
    }

    /**
     * Multiply the given shorts and then run a Montgomery reduce
     *
     * @param a
     * @param b
     * @return
     */
    public modQMulMont(a: number, b: number) {
        return this.byteopsMontgomeryReduce(a * b);
    }

    /**
     * Computes a Montgomery reduction given a 32 Bit Integer
     *
     * @param a
     * @return
     */
    public byteopsMontgomeryReduce(a: number) {
        let u = Utilities.int16(Utilities.uint16(a) * KyberService.paramsQinv);
        let t = u * KyberService.paramsQ;
        t = a - t;
        t >>= 16;
        return Utilities.int16(t);
    }

}