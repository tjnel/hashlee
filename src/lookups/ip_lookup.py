from requests import get

def ip_osint_lookup(ip, log):
    results = []

    #Checking each OSINT Source
    if check_ipvoid(ip):
        log.info(" [[RESULT FOUND]] for {} in IP Void".format(ip))
        results.append('www.ipvoid.com')
    else:
        log.info(" No result in IP Void")

    if check_fusionzero(ip):
        log.info(" [[RESULT FOUND]] for {} in Fusion Zero".format(ip))
        results.append('www.0spam.fusionzero.com')
    else:
        log.info(" No result in Fusion Zerpo")

    if results:
        return results
    else:
        return False

def check_ipvoid(ip):
    check_url = '{}{}'.format('http://www.urlvoid.com/ip/', ip)
    response = get(check_url).text
    if '<i class="glyphicon glyphicon-alert text-danger">' in response:
        return True
    else:
        return False

def check_fusionzero(ip):
    check_url = '{}{}'.format('http://0spam.fusionzero.com/query/?ipaddr=', ip)
    if '<font color=red>LISTED!</font>' in get(check_url).text:
        return True
    else:
        return False

if __name__ == "__main__":
    """
    Main
    """
    ip_osint_lookup()