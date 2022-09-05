import {KyberService} from "../services/kyber.service";

/**
 * Kyber Handshake
 */
export class KyberHandshake {
    private _publicKey: number[] = [];
    private _privateKey: number[] = [];
    private _remotePublicKey: number[] = [];
    private _cipherText: number[] = [];
    private _sharedSecret: number[] = [];
    private _remoteSharedSecret: number[] = [];
    private _remoteCipherText: number[] = [];

    constructor(private kyberService: KyberService) {
    }

    /**
     * Process the remote public key to create a cipher text and shared
     * secret
     * @param remotePublicKey
     * @return cipherText
     */
    public generateCipherTextAndSharedSecret(remotePublicKey: number[]): number[] {
        this.remotePublicKey = remotePublicKey;
        const sharedSecretCipher: number[][] = this.kyberService.encrypt(remotePublicKey);
        this.cipherText = sharedSecretCipher[0];
        this.sharedSecret = sharedSecretCipher[1];
        return this.cipherText;
    }

    /**
     * Process the remote cipher text to generate the same shared
     * secret
     * @param remoteCipherText
     * @return remoteSharedSecret
     */
    public generateRemoteSharedSecret(remoteCipherText: number[]): number[] {
        this.remoteCipherText = remoteCipherText;
        this.remoteSharedSecret = this.kyberService.decrypt(remoteCipherText, this.privateKey);
        return this.remoteSharedSecret;
    }

    get sharedSecret(): number[] {
        return this._sharedSecret;
    }

    set sharedSecret(value: number[]) {
        this._sharedSecret = value;
    }

    get publicKey(): number[] {
        return this._publicKey;
    }

    set publicKey(value: number[]) {
        this._publicKey = value;
    }

    get remoteSharedSecret(): number[] {
        return this._remoteSharedSecret;
    }

    set remoteSharedSecret(value: number[]) {
        this._remoteSharedSecret = value;
    }

    get cipherText(): number[] {
        return this._cipherText;
    }

    set cipherText(value: number[]) {
        this._cipherText = value;
    }

    get remoteCipherText(): number[] {
        return this._remoteCipherText;
    }

    set remoteCipherText(value: number[]) {
        this._remoteCipherText = value;
    }

    get privateKey(): number[] {
        return this._privateKey;
    }

    set privateKey(value: number[]) {
        this._privateKey = value;
    }
    get remotePublicKey(): number[] {
        return this._remotePublicKey;
    }
    set remotePublicKey(value: number[]) {
        this._remotePublicKey = value;
    }
}