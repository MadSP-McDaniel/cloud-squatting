This repository contains analysis and figure code for measuring the traffic observed on public cloud IPs and determining prevalence of potential latent configuration.

# Building

This code was originally built using Docker (`Dockerfile` included). Updates to dependencies may be required for successful building.

# Running

The `ipreuse` script is designed to run all analyses.

# Citing

If you use this code, please cite our related papers:

```
@inproceedings{pauley_measuring_2022,
  title     = {Measuring and {Mitigating} the {Risk} of {IP} {Reuse} on {Public} {Clouds}},
  isbn      = {978-1-66541-316-9},
  url       = {https://www.computer.org/csdl/proceedings-article/sp/2022/131600b523/1CIO7rpcgSs},
  doi       = {10.1109/SP46214.2022.00094},
  language  = {English},
  booktitle = {2022 {IEEE} {Symposium} on {Security} and {Privacy} ({SP})},
  publisher = {IEEE Computer Society},
  author    = {Pauley, Eric and Sheatsley, Ryan and Hoak, Blaine and Burke, Quinn and Beugin, Yohan and McDaniel, Patrick},
  month     = apr,
  year      = {2022},
  note      = {ISSN: 2375-1207},
  pages     = {1523--1523}
}
```

```
@inproceedings{pauley_dscope_2023,
  address   = {Anaheim, CA},
  title     = {{DScope}: {A} {Cloud}-{Native} {Internet} {Telescope}},
  booktitle = {Proceedings of the 32nd {USENIX} {Security} {Symposium} ({USENIX} {Security} 2023, to appear)},
  publisher = {USENIX Association},
  author    = {Pauley, Eric and Barford, Paul and McDaniel, Patrick},
  month     = aug,
  year      = {2023}
}
```