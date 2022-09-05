import {KyberService} from "./kyber.service";

/**
 * Kyber KEM 768 implementation
 */
export class Kyber768Service extends KyberService {

    // Indicates the Kyber version to the rest of the algorithm
    private static paramsK = 3;

    constructor() {
        super(Kyber768Service.paramsK);
    }

    /**
     * String representation of the Kyber version
     */
    public getAlgorithm() {
        return "Kyber768";
    }

}

