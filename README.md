# Iris 
Iris is a neurosymbolic framework that combines LLMs with static analysis for security vulnerability detection. Iris uses LLMs to generate source and sink specifications, and to filter false positive vulnerable paths. 

- [Architecture](#architecture)
- [Environment Setup](#environment-setup)
- [Quickstart](#quickstart)
- [Adding a CWE](#adding-a-cwe)
- [Contributing](#contributing)

## Architecture

## Dataset 
We have curated a dataset of Java projects, containing 120 vulnerabilities across 4 common vulnerability classes. 

[CWE-Bench-Java](https://github.com/Liby99/cwe-bench-java)

## Environment Setup 

## Quickstart

## Adding a CWE (Coming soon)

## Contributing
1. Create a Github issue outlining the piece of work. Solicit feedback from anyone who has recently contributed to the component of the repository you plan to contribute to. 
2. Checkout a branch from main - preferably name your branch [github username]/[brief description of contribution]
3. Create a pull request that refers to the created github issue in the commit message.
4. To link to the github issue, in your commit for example you would simply add in the commit message:
[what the PR does briefly] #[commit issue]
5. Then when you push your commit and create your pull request, Github will automatically link the commit back to the issue. Add more details in the pull request, and request reviewers from anyone who has recently modified related code.
6. After 1 approval, merge your pull request. 

## Citation 
[Arxiv Preprint](https://arxiv.org/abs/2405.17238)
```
@inproceedings{li2024iris,
title={LLM-Assisted Static Analysis for Detecting Security Vulnerabilities},
author={Ziyang Li and Saikat Dutta and Mayur Naik},
booktitle={International Conference on Learning Representations},
year={2025},
url={https://arxiv.org/abs/2405.17238}
}
```

