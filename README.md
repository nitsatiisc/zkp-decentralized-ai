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
The directory structure of the repository is as follows:

* [__zkdoc__](zkdoc):
    * [__src__](zkdoc/src): Containing descriptions of circuits for key NP relations.
        * [__adaptive-snark__](zkdoc/src/adaptive-snark): Commit and Prove extension of Pinocchio zkSNARK implementation in libsnark.
        * [__benchmarks__](zkdoc/src/benchmarks): Containing utility to run the benchmarks
    
* [__depends__](depends): This folder gets generated and populated by installation scripts automatically. It contains external dependencies.



The directory [__zkdoc/src__](zkdoc/src) contains most of the Arithmetic Circuits required for the protocols.
* The file [__zkdoc/src/trusted_ai_utility_gadgets.hpp__](zkdoc/src/trusted_ai_utility_gadgets.hpp) contains descriptions of Arithmetic Circuits for common operations such as _polynomial evaluation_, _hadamard product_ etc. It also contains routines for interpolating polynomials (used in Section 6 of the paper).
* The file [__zkdoc/src/trusted_ai_interactive_gadgets.hpp__](zkdoc/src/trusted_ai_interactive_gadgets.hpp) contains Arithmetic Circuits for key protocols such as "Simulataneous Permutation Check" and "Memory Access Check" as described in Section 4 of the paper.
* The file [__zkdoc/src/trusted_ai_cp_gadgets.hpp__](zkdoc/src/trusted_ai_cp_gadgets.hpp) contains Arithmetic Circuits encoding key dataset operations such as filter, inner-join (Section 5 of the paper) as well as decision tree inference (Section 6). 

The directory [__zkdoc/src/adaptive-snark__](zkdoc/src/adaptive_snark) contains implementation of commit and prove zkSNARK based on scheme described in \[Vee17].
* The file [__zkdoc/src/adaptive-snark/r1cs_adapative_snark.hpp__](zkdoc/src/adaptive_snark/r1cs_adaptive_snark.hpp) contains the implementation of generator, prover and verifier by extending the existing implementation available in _libsnark_. In addition to the circuit specification and the number of public inputs, the generator algorithm takes further two parameters: number of commitment slots (parts of witness which will open a public commitment) and the size of commitment slots. Although in principle, commitment slots can have different sizes, to simplifiy the implementation we assume all slots have the same size (we add dummy variables forced to be 0 when the variables of interest do not exhaust a commitment slot). 
* The file [__zkdoc/src/adaptive-snark/trapdoor_commitment.hpp__](zkdoc/src/adaptive_snark/trapdoor_commitment.hpp) contains the associated commitment scheme.

Finally, the file [__zkdoc/src/benchmarks/run_proto_benchmarks.hpp__] contains code invoking different protocols for different parameters.


--------------------------------------------------------------------------------
Building and Running Benchmarks
--------------------------------------------------------------------------------
The repository includes scripts to easily build and run benchmarks on a Linux System. The following instructions have been tested on Ubuntu 20.04 LTS with
git installed.

* Clone the repository.

   $ git clone https://github.com/nitsatiisc/zkp-decentralized-ai.git
   
* Under the repository root run the following script to install dependencies. This may require elevated priviledges.

   $ /bin/sh install_sandbox_dependencies.sh

* Fetch external projects (such as [https://github.com/scipr-lab/libsnark](libsnark)).

   $ /bin/sh fetch_dependencies.sh

* Build the external projects.

   $ /bin/sh build_sandbox_dependencies.sh
   
* Build the benchmarking binary

   $ /bin/sh build_crypto_utility.sh
   
The above steps create a depends folder under the repository root where all external projects are pulled. It also creates a build folder under which the benchmarking utility is built. 

* Run the benchmarks using:

   $ ./build/zkdoc/run_proto_benchmarks

* After the benchmarks run (which can take quite a while), additional files containing the statistics of the protocols (e.g prover time, verifier time, number of gates in the circuit) are created in the folder where the benchmarking script was invoked (Note that the total run time of the script is greater than the proving times reported in the paper, as one time parameters are re-generated for each set of parameters).

--------------------------------------------------------------------------------
Protocols Benchmarked
--------------------------------------------------------------------------------



--------------------------------------------------------------------------------
Circuit Descriptions
--------------------------------------------------------------------------------


--------------------------------------------------------------------------------
References
--------------------------------------------------------------------------------


\[PGHR13] [
  _Pinocchio: Nearly Practical Verifiable Computation_
](http://eprint.iacr.org/2013/279),
  Bryan Parno, Craig Gentry, Jon Howell, Mariana Raykova,
  IEEE Symposium on Security and Privacy (Oakland) 2013

[SCIPR Lab]: http://www.scipr-lab.org/ (Succinct Computational Integrity and Privacy Research Lab)
