Code was created to download reports from Google Threat Intelligence. 
Original purpose is to download reports for analysis, specifically using NotebookLM to generate insights from the reports.

Run the code with 
``` bash
python report_downloader.py
```

You need to enter the: 
1. Directory to save reports
2. Search Query (eg, APT42, Scattered Spider, etc)
3. Origins (GTI or Crowdsourced)
4. Number of days back to search for reports