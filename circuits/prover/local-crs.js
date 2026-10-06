// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
//
// A stand-in for bb.js's browser reference-string loader, swapped in at bundle
// time. The upstream loader downloads the BN254 points from Aztec's CDN; this
// one reads them from files shipped with the site (`frontend/crs/`), so
// proving makes no third-party request.
//
// The points only have to be right for the prover's own benefit. Soundness
// rests on the verifier's verification key and G2 point, which are baked into
// the on-chain HonkVerifier; wrong points here can only produce proofs that
// fail to verify.

const BASE = new URL("../../crs/", import.meta.url);

async function load (name) {
  const response = await fetch(new URL(name, BASE));
  if (!response.ok) {
    throw new Error(`Could not load the proving reference string ${name} `
      + `(${response.status}). It ships with the site under crs/.`);
  }
  return new Uint8Array(await response.arrayBuffer());
}

export class Crs {
  constructor (numPoints) {
    this.numPoints = numPoints;
  }

  static async new (numPoints) {
    const crs = new Crs(numPoints);
    await crs.init();
    return crs;
  }

  async init () {
    const g1 = await load("bn254_g1_compressed.dat");
    if (g1.length < this.numPoints * 32) {
      throw new Error(`The site ships ${g1.length / 32} reference points; `
        + `proving needs ${this.numPoints}.`);
    }
    this.g1Data = g1.subarray(0, this.numPoints * 32);
    this.g2Data = await load("bn254_g2.dat");
  }

  getG1Data () {
    return this.g1Data;
  }

  getG2Data () {
    return this.g2Data;
  }

  async cacheUncompressed () {}
}

export class GrumpkinCrs {
  constructor (numPoints) {
    this.numPoints = numPoints;
  }

  static async new (numPoints) {
    const crs = new GrumpkinCrs(numPoints);
    await crs.init();
    return crs;
  }

  // UltraHonk proving never touches the Grumpkin curve, so no points ship.
  async init () {
    this.numPoints = 0;
    this.g1Data = new Uint8Array(0);
  }

  getG1Data () {
    return this.g1Data;
  }
}
