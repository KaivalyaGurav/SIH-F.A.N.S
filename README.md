# SIH-F.A.N.S
Project For SIH Download the tool and start using


Usage Instructions (Step-by-Step for Judges & Hackathon Submission)

 1. **Install the prerequisites**
- Python 3.x
- Subfinder
- HTTPX
- Nuclei (optional)
- FFUF
- waybackurls
- OpenAI Python client (`pip install openai`)
- python-docx (`pip install python-docx`)
- Ensure the required wordlists exist at the specified paths.

### 2. **Set your OpenRouter API key**
- Replace the value of `OPENROUTER_API_KEY` in the file with your own key if needed.

### 3. **Run the tool**
**Basic Command**
```shell
python3 sihHOOKSV4.py example.com
```
- Replace `example.com` with the target domain you want to assess.

**Skip nuclei scan (optional)**
```shell
python3 sihHOOKSV4.py example.com --skip-nuclei
```

### 4. **Review the Output**
- All results and the final AI-generated security report are stored in a folder named after the target domain.
- The main report will be saved as a DOCX file at:  
  `./example.com/report/example.com_report.docx`

### 5. **What does it do?**
- Finds subdomains of the target.
- Checks which subdomains are alive.
- Optionally runs vulnerability scans with Nuclei.
- Fuzzes for virtual hosts and directories.
- Scrapes historical URLs via Wayback Machine.
- Fuzzes for XSS and SQLi vulnerabilities.
- Aggregates all findings.
- Generates a professional report using AI.
