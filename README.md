# IRIS 
IRIS is a neurosymbolic framework that combines LLMs with static analysis for security vulnerability detection. IRIS uses LLMs to generate source and sink specifications, and to filter false positive vulnerable paths. 

- [Architecture](#architecture)
- [Environment Setup](#environment-setup)
- [Quickstart](#quickstart)
- [Supported CWEs](#supported-cwes)
- [Supported Models](#supported-models)
- [Adding a CWE](#adding-a-cwe)
- [Contributing](#contributing-and-feedback)

## Architecture

![iris architecture](iris_arch.png)

1. First we make CodeQL queries to collect external APIs in the project and all internal function parameters. 
2. We provide the LLM the external APIs to find potential sources, sinks, and taint propagators. In another query, we provide the LLM the internal function parameters for potential sources.
3. Given the results from step 2, we use them to build project specific CodeQL queries. 
4. Then we run the queries from step 3 to find vulnerabilities and post-process the results. 
5. We provide the LLM the post-processed results to filter for false positives, false negatives, and whether a CWE is detected.  

## Dataset 
We have curated a dataset of Java projects, containing 120 vulnerabilities across 4 common vulnerability classes. 

[CWE-Bench-Java](https://github.com/seal-research/cwe-bench-java)
## Environment Setup
First, clone the repository. We have included `cwe-bench-java` as a submodule, so use the following command the clone correctly
```bash
$ git clone https://github.com/seal-research/iris --recursive
```
### 1. Conda environment  
Run `scripts/setup_environment.sh`. 
```bash
$ chmod +x scripts/setup_environment.sh
$ bash ./scripts/setup_environment.sh
```
This will do the following:
- creates a conda environment specified by environment.yml
- installs our [patched version of CodeQL](https://github.com/seal-research/iris/releases/tag/codeql-0.8.3-patched). This version of CodeQL **is necessary** for IRIS.
- creates a directory to store CodeQL databases. 
### 2. Fetch and build Java projects
We have included CWE-Bench-Java as a submodule in IRIS in the data folder. We have also provided scripts to fetch and build Java projects to be used with IRIS. 

For building, we need Java distributions as well as Maven and Gradle for package management. In case you have a different system than Linux x64, please modify `data/cwe-bench-java/scripts/jdk_version.json`, `data/cwe-bench-java/scripts/mvn_version.json`, and `data/cwe-bench-java/scripts/gradle_version.json` to specify the corresponding JDK/MVN/Gradle files. In addition, please prepare 3 versions of JDK and put them under the java-env folder. Oracle requires an account to download the JDKs, and we are unable to provide an automated script. Download from the following URLs:

JDK 7u80: https://www.oracle.com/java/technologies/javase/javase7-archive-downloads.html

JDK 8u202: https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html

JDK 17: https://www.oracle.com/java/technologies/javase/jdk17-archive-downloads.html

At this point, your `java-env` directory should look like 
```
- data/cwe-bench-java/java-env/
  - jdk-7u80-linux-x64.tar.gz
  - jdk-8u202-linux-x64.tar.gz
  - jdk-17_linux-x64_bin.tar.gz
```

Now run the fetch and build script. You can also choose to fetch and not build, or specify a set of projects. You can find project names in the project_slug column in `cwe-bench-java/data/build_info.csv`.
```bash
# fetch projects and build them
$ python3 data/cwe-bench-java/scripts/setup.py

# fetch projects and don't build them
$ python3 data/cwe-bench-java/scripts/setup.py --no-build

# example - only build projects under CWE-022 and CWE-078
$ python3 data/cwe-bench-java/scripts/setup.py --cwe CWE-022 CWE-078 

# example - only build keycloack parojects 
$ python3 data/cwe-bench-java/scripts/setup.py --filter keycloak 

# example - do not build any apache related projects
$ python3 data/cwe-bench-java/scripts/setup.py --exclude apache       
```
This will create the `build-info` and `project-sources` directories. It will also install JDK, Maven, and Gradle versions used to build the projects in `cwe-bench-java`. `build-info` is used to store build information and `project-sources` is where the fetched projects are stored.

### 3. Generate CodeQL databases
To use CodeQL, you will need to generate a CodeQL database for each project. We have provided a script to automate this. The script will generate databases for all projects found in `data/cwe-bench-java/project-sources`. To generate a database for a specific project, use the `--project` argument. 
```bash
# build CodeQL databases for all projects in project-sources
$ python3 scripts/build_codeql_dbs.py 

# build a specific CodeQL database given the project slug
$ python3 scripts/build_codeql_dbs.py --project apache__camel_CVE-2018-8041_2.20.3
```

### 4. Check IRIS directory configuration in `src/config.py`
By running the provided scripts, you won't have to modify `src/config.py`. Double check that the paths in the configuration are correct. Each path variable has a comment explaining its purpose.

## Quickstart
Make sure you have followed all of the environment setup instructions before proceeding! 

`src/neusym_vul.py` is used to analyze one specific project. `src/neusym_vul_for_query.py` is used to analyze multiple projects. Results are written to the `output` directory.

See the [Supported CWEs](#supported-cwes) section for `--query` arguments and the [Supported Models](#supported-models) section for `--llm` arguments.

The following is an example of using IRIS to analyze zerotunaround for vulnerabilities that fall under CWE-022, using GPT-4. Query `cwe-022wLLM` refers to [cwe-22 path traversal](https://cwe.mitre.org/data/definitions/22.html). 
```bash
$ python3 src/neusym_vul.py --query cwe-022wLLM --run-id <SOME_ID> --llm gpt-4 zeroturnaround__zt-zip_CVE-2018-1002201_1.12
```


The following is an example of using IRIS to analyze all of the cwe-java-bench projects for vulnerabilities that fall under CWE-022, using `gemma-2-27b-tai` (hosted by TogetherAI).
```bash
$ python3 src/neusym_vul_for_query.py --query cwe-022wLLM --run-id <SOME_ID> --llm gemma-2-27b-tai
```

## Supported CWEs
Here are the following CWEs supported, that you can specify as an argument to `--query` when using `src/neusym_vul.py` and `src/neusym_vul_for_query.py`. 

- `cwe-022wLLM` - [CWE-022](https://cwe.mitre.org/data/definitions/22.html) (Path Traversal)
- `cwe-078wLLM` - [CWE-078](https://cwe.mitre.org/data/definitions/78.html) (OS Command Injection)
- `cwe-079wLLM` - [CWE-079](https://cwe.mitre.org/data/definitions/79.html) (Cross-Site Scripting)
- `cwe-094wLLM` - [CWE-094](https://cwe.mitre.org/data/definitions/94.html) (Code Injection)



## Supported Models
We support the following models with our models API wrapper (found in `src/models`) in the project. Listed below are the arguments you can use for `--llm` when using `src/neusym_vul.py` and `src/neusym_vul_for_query.py`. You're free to use your own way of instantiating models or adding on to the existing library. Some of them require your own API key or license agreement on HuggingFace. 

### Codegen
- `codegen-16b-multi`
- `codegen25-7b-instruct`
- `codegen25-7b-multi`

### Codellama
#### Standard Models
- `codellama-70b-instruct`
- `codellama-34b`
- `codellama-34b-python`
- `codellama-34b-instruct`
- `codellama-13b-instruct`
- `codellama-7b-instruct`

### CodeT5p
- `codet5p-16b-instruct`
- `codet5p-16b`
- `codet5p-6b`
- `codet5p-2b`

### DeepSeek
- `deepseekcoder-33b`
- `deepseekcoder-7b`
- `deepseekcoder-v2-15b`

### Gemini
- `gemini-1.5-pro`
- `gemini-1.5-flash`
- `gemini-pro`
- `gemini-pro-vision`
- `gemini-1.0-pro-vision`

### Gemma
- `gemma-7b`
- `gemma-7b-it`
- `gemma-2b`
- `gemma-2b-it`
- `codegemma-7b-it`
- `gemma-2-27b`
- `gemma-2-9b`

### GPT
- `gpt-4`
- `gpt-3.5`
- `gpt-4-1106`
- `gpt-4-0613`

### LLaMA
#### LLaMA-2
- `llama-2-7b-chat`
- `llama-2-13b-chat`
- `llama-2-70b-chat`
- `llama-2-7b`
- `llama-2-13b`
- `llama-2-70b`

#### LLaMA-3
- `llama-3-8b`
- `llama-3.1-8b`
- `llama-3-70b`
- `llama-3.1-70b`
- `llama-3-70b-tai`

### Mistral
- `mistral-7b-instruct`
- `mixtral-8x7b-instruct`
- `mixtral-8x7b`
- `mixtral-8x22b`
- `mistral-codestral-22b`

### Qwen
- `qwen2.5-coder-7b`
- `qwen2.5-coder-1.5b`
- `qwen2.5-14b`
- `qwen2.5-32b`
- `qwen2.5-72b`

### StarCoder
- `starcoder`
- `starcoder2-15b`

### WizardLM
#### WizardCoder
- `wizardcoder-15b`
- `wizardcoder-34b-python`
- `wizardcoder-13b-python`

#### WizardLM Base
- `wizardlm-70b`
- `wizardlm-13b`
- `wizardlm-30b`


## Adding a CWE
Coming soon! 

## Contributing and Feedback
Feel free to address any open issues or add your own issue and fix. We love feedback! Please adhere to the following guidelines. 

1. Create a Github issue outlining the piece of work. Solicit feedback from anyone who has recently contributed to the component of the repository you plan to contribute to. 
2. Checkout a branch from `main` - preferably name your branch `[github username]/[brief description of contribution]`
3. Create a pull request that refers to the created github issue in the commit message.
4. To link to the github issue, in your commit for example you would simply add in the commit message:
[what the PR does briefly] #[commit issue]
5. Then when you push your commit and create your pull request, Github will automatically link the commit back to the issue. Add more details in the pull request, and request reviewers from anyone who has recently modified related code.
6. After 1 approval, merge your pull request.

## Citation 
Consider citing our paper:
```
@inproceedings{li2025iris,
title={LLM-Assisted Static Analysis for Detecting Security Vulnerabilities},
author={Ziyang Li and Saikat Dutta and Mayur Naik},
booktitle={International Conference on Learning Representations},
year={2025},
url={https://arxiv.org/abs/2405.17238}
}
```
[Arxiv Link](https://arxiv.org/abs/2405.17238)
