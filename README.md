[ITA]
Application_traceroute è un suite di 4 tools utili nella fase di discovery.
Il primo tool da utilizzare è application_traceroute:
  
      python AppTraceroute/application_traceroute2.py --help                          
      usage: application_traceroute2.py [-h] [--forbidden-endpoint FORBIDDEN_ENDPOINT] [--skip-forbidden-tests] target

      Application Stack Traceroute - WAF/Proxy/Backend Chain Analysi

      positional arguments:
        target                Target URL to analyze
        options:
        -h, --help            show this help message and exit
        --forbidden-endpoint FORBIDDEN_ENDPOINT:  Known 403/401 endpoint for bypass testing (e.g. https://target.com/admin)
        --skip-forbidden-tests:    Skip tests requiring forbidden endpoint

Il quale ricostruisce lo stack tecnologico, ne individua le discrepanze e genera dei possibili bypass testandoli e verificandoli. Il risultato viene esportato in 2 file: 1) *.txt e 2) *.json
Il file in json contieni i bypass e può/deve essere usato nei 2 tool successivi, il secondo tool:
            
    python BypassValidator/bypass_validator.py bypasses_www.XXXXX.it_1753971402.json

Il quale riverifica e ricontrolla la validità dei bypass appena generati.
Oppure può essere utlizzato nel terzo tool il quale esegue un crawl dell'applicazione in scope, trova gli endpoint, per gli endpoint cerca i punti di iniezione, ne stabilisce una probabile vulnerabilità ed esegue un fuzz prendedo dalle wordlist 
maggiormente usate, fuzzdb/SecList/PayloadAllTheThing:

    python SmartCrawler/smart_vuln_crawler2.py https://www.target.it --bypass-file AppTraceroute/bypass_validation_www.target.it_1753971634.json --wordlist-base ~/path_to_worlist
    
    usage: smart_vuln_crawler2.py [-h] [--depth DEPTH] [--max-pages MAX_PAGES] [--output OUTPUT] [--wordlist-base WORDLIST_BASE] [--discovery-limit DISCOVERY_LIMIT] [--skip-discovery]
                              [--bypass-file BYPASS_FILE] [-v] [--auth-type {basic,bearer,cookie,form,custom_header}] [--auth-username AUTH_USERNAME] [--auth-password AUTH_PASSWORD]
                              [--auth-token AUTH_TOKEN] [--auth-login-url AUTH_LOGIN_URL] [--auth-cookies AUTH_COOKIES] [--auth-headers AUTH_HEADERS] [--auth-config AUTH_CONFIG]
                              target

[ENG]

Application_traceroute is a suite of 4 tools useful in the discovery phase.
The first tool to use is application_traceroute:

      python AppTraceroute/application_traceroute2.py --help                          
      usage: application_traceroute2.py [-h] [--forbidden-endpoint FORBIDDEN_ENDPOINT] [--skip-forbidden-tests] target

      Application Stack Traceroute - WAF/Proxy/Backend Chain Analysi

      positional arguments:
        target                Target URL to analyze
        options:
        -h, --help            show this help message and exit
        --forbidden-endpoint FORBIDDEN_ENDPOINT:  Known 403/401 endpoint for bypass testing (e.g. https://target.com/admin)
        --skip-forbidden-tests:    Skip tests requiring forbidden endpoint


Which reconstructs the technology stack, identifies discrepancies and generates possible bypasses by testing and verifying them. The result is exported in 2 files: 1) *.txt and 2) *.json
The json file contains the bypasses and can/must be used in the next 2 tools, the second tool:

    python BypassValidator/bypass_validator.py bypasses_www.XXXXX.it_1753971402.json


Which rechecks and rechecks the validity of the bypasses just generated.
Or it can be used in the third tool that crawls the application in scope, finds the endpoints, searches for the endpoints, establishes a probable vulnerability and performs a fuzz taking from the most used wordlists,
fuzzdb/SecList/PayloadAllTheThing:

    python SmartCrawler/smart_vuln_crawler2.py https://www.target.it --bypass-file AppTraceroute/bypass_validation_www.target.it_1753971634.json --wordlist-base ~/path_to_worlist
    
    usage: smart_vuln_crawler2.py [-h] [--depth DEPTH] [--max-pages MAX_PAGES] [--output OUTPUT] [--wordlist-base WORDLIST_BASE] [--discovery-limit DISCOVERY_LIMIT] [--skip-discovery]
                              [--bypass-file BYPASS_FILE] [-v] [--auth-type {basic,bearer,cookie,form,custom_header}] [--auth-username AUTH_USERNAME] [--auth-password AUTH_PASSWORD]
                              [--auth-token AUTH_TOKEN] [--auth-login-url AUTH_LOGIN_URL] [--auth-cookies AUTH_COOKIES] [--auth-headers AUTH_HEADERS] [--auth-config AUTH_CONFIG]
                              target
