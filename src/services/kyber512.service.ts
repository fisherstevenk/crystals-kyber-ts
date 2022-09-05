import {KyberService} from "./kyber.service";

/**
 * Kyber KEM 512 implementation
 */
export class Kyber512Service extends KyberService {

    // Indicates the Kyber version to the rest of the algorithm
    private static paramsK = 2;

    constructor() {
        super(Kyber512Service.paramsK);
    }

    /**
     * String representation of the Kyber version
     */
    public getAlgorithm() {
        return "Kyber512";
    }
}

