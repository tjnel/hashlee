from requests import get

def hash_osint_lookup(hash, log):
    results = []

    #Checking each OSINT Source
    return False
"""
    if check_cymru(hash):
        log.info(" [[RESULT FOUND]] for {} in CYMRU".format(hash))
        results.append('www.malware.hash.cymru.com')
    else:
        log.info(" No result in URL Void")

    if check_siteadvisor(hash):
        log.info(" [[RESULT FOUND]] for {} in McAfee SiteAdvisor".format(hash))
        results.append('www.siteadvisor.com')
    else:
        log.info(" No result in URL Void")

    if results:
        return results
    else:
        return False

## SAMPLE HASH LOOKUPS
def check_cyrmu(hash):
    check_url = '{}{}'.format(hash, '.malware.hash.cymru.com')
    if '' in whois.whois(check_url):
        return True
    else:
        return False

def check_option1(hash):
    check_url = '{}{}'.format('https://www.siteadvisor.com/sitereport.html?url=', hash)
    if '<img src="/img/danger-icon.svg">' in get(check_url).text:
        return True
    else:
        return False
"""

if __name__ == "__main__":
    """
    Main
    """
    hash_osint_lookup()