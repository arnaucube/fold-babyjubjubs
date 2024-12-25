# fold-babyjubjubs

Repo folding BabyJubJub EdDSA signatures using [arkeddsa](https://github.com/kilic/arkeddsa), showcasing usage of [Sonobe](https://github.com/privacy-scaling-explorations/sonobe) with [Arkworks](https://github.com/arkworks-rs).

The main idea is to prove $z_n = F(F(...~F(F(F(z_0)))))$, where $n$ is the number of BabyJubJub EdDSA signature verifications ($F$) that we compute. Proving this in a 'normal' R1CS circuit for a large $n$ would be too costly, but with folding we can manage to prove it in a reasonable time span.

For more info about Sonobe, check out [Sonobe's docs](https://privacy-scaling-explorations.github.io/sonobe-docs).

<p align="center">
    <img src="https://privacy-scaling-explorations.github.io/sonobe-docs/imgs/folding-main-idea-diagram.png" style="width:70%;" />
</p>


### Usage

- `cargo test --release -- --nocapture`
