--------------------------------------------------------------------------
Zero Knowledge Proofs for Decentralized AI Pipelines
--------------------------------------------------------------------------
This repository contains software artefacts used to obtain the experimental results in the paper "Using Zero Knowledge Proofs for Decentralized AI Pipelines"
The repository contains: 
- code to benchmark various protocols discussed in the paper,
- specification of Arithmetic circuits for different NP relations discussed in the paper using libsnark backend.
- Extension of Pinocchio protocol to support commit and prove capabilities based on Adaptive-Pinocchio scheme in the paper (Adaptive Pinocchio).

[TOC]



--------------------------------------------------------------------------------
Repository Overview
--------------------------------------------------------------------------------



--------------------------------------------------------------------------------
Building and Running Benchmarks
--------------------------------------------------------------------------------


--------------------------------------------------------------------------------
Protocols Benchmarked
--------------------------------------------------------------------------------



--------------------------------------------------------------------------------
Circuit Descriptions
--------------------------------------------------------------------------------



--------------------------------------------------------------------------------
Directory structure
--------------------------------------------------------------------------------

The directory structure of the repository is as follows:

* [__zkdoc__](zkdoc):
    * [__src__](zkdoc/src): Containing descriptions of circuits for key NP relations.
        * [__adaptive-snark__](zkdoc/src/adaptive-snark): Commit and Prove extension of Pinocchio zkSNARK implementation in libsnark.
        * [__benchmarks__](zkdoc/src/benchmarks): Containing utility to run the benchmarks
    
* [__depends__](depends): This folder gets generated and populated by installation scripts automatically. It contains external dependencies.


--------------------------------------------------------------------------------
References
--------------------------------------------------------------------------------

\[BBFR15] [
  _ADSNARK: nearly practical and privacy-preserving proofs on authenticated data_
](https://eprint.iacr.org/2014/617),
  Michael Backes, Manuel Barbosa, Dario Fiore, Raphael M. Reischuk,
  IEEE Symposium on Security and Privacy (Oakland) 2015

\[BCCT12] [
  _From extractable collision resistance to succinct non-Interactive arguments of knowledge, and back again_
](http://eprint.iacr.org/2011/443),
  Nir Bitansky, Ran Canetti, Alessandro Chiesa, Eran Tromer,
  Innovations in Computer Science (ITCS) 2012

\[BCCT13] [
  _Recursive composition and bootstrapping for SNARKs and proof-carrying data_
](http://eprint.iacr.org/2012/095)
  Nir Bitansky, Ran Canetti, Alessandro Chiesa, Eran Tromer,
  Symposium on Theory of Computing (STOC) 13

\[BCGTV13] [
  _SNARKs for C: Verifying Program Executions Succinctly and in Zero Knowledge_
](http://eprint.iacr.org/2013/507),
  Eli Ben-Sasson, Alessandro Chiesa, Daniel Genkin, Eran Tromer, Madars Virza,
  CRYPTO 2013

\[BCIOP13] [
  _Succinct non-interactive arguments via linear interactive Proofs_
](http://eprint.iacr.org/2012/718),
  Nir Bitansky, Alessandro Chiesa, Yuval Ishai, Rafail Ostrovsky, Omer Paneth,
  Theory of Cryptography Conference 2013

\[BCTV14a] [
  _Succinct non-interactive zero knowledge for a von Neumann architecture_
](http://eprint.iacr.org/2013/879),
  Eli Ben-Sasson, Alessandro Chiesa, Eran Tromer, Madars Virza,
  USENIX Security 2014

\[BCTV14b] [
  _Scalable succinct non-interactive arguments via cycles of elliptic curves_
](https://eprint.iacr.org/2014/595),
  Eli Ben-Sasson, Alessandro Chiesa, Eran Tromer, Madars Virza,
  CRYPTO 2014

\[CTV15] [
  _Cluster computing in zero knowledge_
](https://eprint.iacr.org/2015/377),
  Alessandro Chiesa, Eran Tromer, Madars Virza,
  Eurocrypt 2015

\[DFGK14] [
  Square span programs with applications to succinct NIZK arguments
](https://eprint.iacr.org/2014/718),
  George Danezis, Cedric Fournet, Jens Groth, Markulf Kohlweiss,
  ASIACCS 2014

\[Groth16] [
  On the Size of Pairing-based Non-interactive Arguments
](https://eprint.iacr.org/2016/260),
  Jens Groth,
  EUROCRYPT 2016

\[GM17] [
  Snarky Signatures: Minimal Signatures of Knowledge from Simulation-Extractable
  SNARKs
](https://eprint.iacr.org/2017/540),
  Jens Groth and Mary Maller,
  IACR-CRYPTO-2017

\[GGPR13] [
  _Quadratic span programs and succinct NIZKs without PCPs_
](http://eprint.iacr.org/2012/215),
  Rosario Gennaro, Craig Gentry, Bryan Parno, Mariana Raykova,
  EUROCRYPT 2013

\[ate-pairing] [
  _High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig Curves_
](https://github.com/herumi/ate-pairing),
  MITSUNARI Shigeo, TERUYA Tadanori

\[PGHR13] [
  _Pinocchio: Nearly Practical Verifiable Computation_
](http://eprint.iacr.org/2013/279),
  Bryan Parno, Craig Gentry, Jon Howell, Mariana Raykova,
  IEEE Symposium on Security and Privacy (Oakland) 2013

[SCIPR Lab]: http://www.scipr-lab.org/ (Succinct Computational Integrity and Privacy Research Lab)
