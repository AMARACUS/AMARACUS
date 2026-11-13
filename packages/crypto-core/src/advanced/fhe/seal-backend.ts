/**
 * AMARACUS — Phase 9: Microsoft SEAL Backend for FHE
 * Encapsulates the WebAssembly SEAL instance, encryption parameters, and context.
 */

// Use require for node-seal CJS compatibility
// eslint-disable-next-line @typescript-eslint/no-var-requires
const nodeSeal = require('node-seal');

export class SealBackend {
  private static sealInstance: any = null;

  public static async getInstance(): Promise<any> {
    if (!this.sealInstance) {
      this.sealInstance = await nodeSeal();
    }
    return this.sealInstance;
  }

  /**
   * Creates context for BFV exact integer homomorphic encryption
   */
  public static async createBfvContext(polyModulusDegree: 4096 | 8192 = 4096, plainModulusBits: number = 20): Promise<{
    seal: any;
    context: any;
    encParms: any;
  }> {
    const seal = await this.getInstance();
    const encParms = seal.EncryptionParameters(seal.SchemeType.bfv);
    encParms.setPolyModulusDegree(polyModulusDegree);
    encParms.setCoeffModulus(seal.CoeffModulus.BFVDefault(polyModulusDegree));
    encParms.setPlainModulus(seal.PlainModulus.Batching(polyModulusDegree, plainModulusBits));

    const context = seal.Context(encParms, true, seal.SecurityLevel.tc128);
    if (!context.parametersSet()) {
      throw new Error('SEAL parameters are not valid for BFV scheme');
    }

    return { seal, context, encParms };
  }
}
