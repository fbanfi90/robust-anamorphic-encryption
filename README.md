# ElGamal Robust Anamorphic Encryption PoC

This repository contains a **small, self-contained proof-of-concept** implementation of the **robust anamorphic encryption** construction instantiated with **ElGamal**, corresponding to an updated version of the code included in the appendix of the paper https://eprint.iacr.org/2023/249.pdf

The goal is **not** production security or performance. It is meant to **demonstrate correctness** of the proposed construction by:
1. **Encrypting anamorphically** many times and showing that decryption recovers:
   - the *regular* plaintext message via standard decryption, and
   - the *covert* message via anamorphic decryption.
2. **Encrypting normally** many times and showing that:
   - standard decryption returns the correct plaintext, while
   - anamorphic decryption correctly indicate that there is no covert message.

## Run

```bash
python3 elgamal.py
```

The script prints parameters and then runs two test phases:

### 1) Normal encryption tests ($\textsf{Enc} \rightarrow \textsf{Dec}$ and $\textsf{Enc} \rightarrow \textsf{aDec}$)
For many random plaintext messages $m$ it repeatedly:
- encrypts normally ($\textsf{Enc}$) to produce a ciphertext $(c_0,c_1)$
- decrypts normally ($\textsf{Dec}$) to recover $m$
- decrypts anamorphically ($\textsf{aDec}$), which should return $\bot$ (`-1`)

### 2) Anamorphic encryption tests ($\textsf{aEnc} \rightarrow \textsf{Dec}$ and $\textsf{aEnc} \rightarrow \textsf{aDec}$)
For a fixed $(m, \hat m)$ it repeatedly:
- encrypts anamorphically ($\textsf{aEnc}$) to produce a ciphertext $(c_0,c_1)$
- decrypts normally ($\textsf{Dec}$) to recover $m$
- decrypts anamorphically ($\textsf{aDec}$) to recover $\hat m$

## Notes / Caveats

- This is a **didactic PoC** only.
- Parameters in the script are small / toy (a larger group is shown commented out).
- Randomness uses Python's `random` module for simplicity.
- Unlike the paper, this version unifies the counter space into a single parameter $\sigma$.[^1]

[^1]: The original paper uses two parameters $\sigma$ and $\tau$, splitting the PRF input as $(x,y)$ with $x\in[\sigma]$ and $y\in[\tau]$ to guarantee that at least the $y$-half could always be extracted from the ciphertext. This version eliminates that constraint by allowing full counter recovery via brute-force search, making $y$ and hence $\tau$ redundant: security depends only on $\sigma$ (search difficulty), not on the PRF input's internal structure.
