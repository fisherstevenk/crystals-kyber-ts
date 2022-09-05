import {KyberService} from "./kyber.service";

/**
 * Kyber KEM 1024 implementation
 */
export class Kyber1024Service extends KyberService {

    // Indicates the Kyber version to the rest of the algorithm
    private static paramsK = 4;

    constructor() {
        super(Kyber1024Service.paramsK);
    }

    /**
     * String representation of the Kyber version
     */
    public getAlgorithm() {
        return "Kyber1024";
    }

}

