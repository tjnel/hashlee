from requests import get

def url_osint_lookup(url, log):
    results = []

    #Checking each OSINT Source
    if check_urlvoid(url):
        log.info(" [[RESULT FOUND]] for {} in URL Void".format(url))
        results.append('www.urlvoid.com')
    else:
        log.info(" No result in URL Void")

    if check_siteadvisor(url):
        log.info(" [[RESULT FOUND]] for {} in McAfee SiteAdvisor".format(url))
        results.append('www.siteadvisor.com')
    else:
        log.info(" No result in URL Void")

    if results:
        return results
    else:
        return False

def check_urlvoid(url):
    check_url = '{}{}'.format('http://www.urlvoid.com/scan/', url)
    if '<i class="glyphicon glyphicon-alert text-danger">' in get(check_url).text:
        return True
    else:
        return False

def check_siteadvisor(url):
    check_url = '{}{}'.format('https://www.siteadvisor.com/sitereport.html?url=', url)
    if '<img src="/img/danger-icon.svg">' in get(check_url).text:
        return True
    else:
        return False

if __name__ == "__main__":
    """
    Main
    """
    url_osint_lookup()