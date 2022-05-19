import ipaddress


# region URL Features

Legitimate = 0
Fishing = 1
Suspicious = -1


# 1. Domain
def getDomain(urlData):
    Domain = urlData['URLs'].str.extract(r'^https?://(.*?)/', expand=False)
    Domain = Domain.str.replace(r'www.', '', regex=True)
    urlData['Domain'] = Domain
    return Domain


# 2. URL length
def getURL_Length(urlData):
    URL_length = urlData['URLs'].str.len()
    URL_length = URL_length.apply(lambda x: Fishing if x > 60
                                  else (Legitimate if x <= 48 else Suspicious))
    urlData['URL_Length'] = URL_length

    return URL_length


# 2. Domain length
def getDomain_Length(urlData):
    Domain_length = getDomain(urlData).str.len()
    Domain_length = Domain_length.apply(lambda x: Fishing if x > 18 or x < 7
                                        else (Legitimate if x <= 12 else Suspicious))
    urlData['Domain_Length'] = Domain_length

    return Domain_length


# 3. URL Depth
def getURL_Depth(urlData):
    URL_depth = urlData['URLs'].str.count('/')

    URL_depth = URL_depth.apply(lambda x: Fishing if x > 4
                                else (Legitimate if x <= 3 else Suspicious))
    urlData['URL_depth'] = URL_depth

    return URL_depth


# 4. URL @ symbol presence
def getURL_AtSymbol(urlData):
    URL_atSymbol = urlData['URLs'].str.contains('@')

    URL_atSymbol = URL_atSymbol.apply(lambda x: Fishing if x is True
                                      else Legitimate)
    urlData['URL_atSymbol'] = URL_atSymbol

    return URL_atSymbol


# 5. IP address presence in URL
def getURL_IP(urlData):
    URL_IP = ''
    try:
        ipaddress.ip_address(urlData['URLs'])
        URL_IP = Fishing
    except:
        URL_IP = Legitimate

    urlData['URL_IP'] = URL_IP
    return URL_IP


# 6. Transport layer security (TLS) presence in URL
def getURL_HTTPs(urlData):
    URL_HTTPs = urlData['URLs'].str.contains('https://')

    URL_HTTPs = URL_HTTPs.apply(lambda x: Fishing if x is False
                                else Legitimate)
    urlData['URL_HTTPS'] = URL_HTTPs

    return URL_HTTPs


# 7. HTTP/HTTPS presence in Domain
def getURLDomain_HTTP(urlData):
    URL_HTTP = getDomain(urlData).str.contains('http')

    URL_HTTP = URL_HTTP.apply(lambda x: Fishing if x is True
                              else Legitimate)
    urlData['Domain_HTTP'] = URL_HTTP

    return URL_HTTP


# 8. // Redirect postion in URL
def getURL_RedirectPosition(urlData):
    URL_RedirectPosition = urlData['URLs'].str.rfind('//')

    URL_RedirectPosition = URL_RedirectPosition.apply(lambda x: Fishing if x > 7 or x < 6
                                                      else Legitimate)
    urlData['URL_RedirectPosition'] = URL_RedirectPosition

    return URL_RedirectPosition


# 9. Hyphen in URL Domain
def getURL_HyphenInDomain(urlData):
    URL_Hyphen = getDomain(urlData).str.contains('-')

    URL_Hyphen = URL_Hyphen.apply(lambda x: Fishing if x is True
                                  else Legitimate)
    urlData['URL_HyphenInDomain'] = URL_Hyphen

    return URL_Hyphen


# 10. Number of '.' in URL Domain
def getURL_Dot(urlData):
    URL_Dot = getDomain(urlData).str.count('\.')

    URL_Dot = URL_Dot.apply(lambda x: Fishing if x > 2
                            else (Legitimate if x <= 1 else Suspicious))
    urlData['URL_DotsNo'] = URL_Dot

    return URL_Dot


# 11. Non ASCII characters in URL
def getURL_ASCII(urlData):
    URL_ASCHII = urlData['URLs'].str.contains('[^\x00-\x7F]' or '[^\x00-\xFF]' or '[^[:ascii:]]')

    URL_ASCHII = URL_ASCHII.apply(lambda x: Fishing if x is True else Legitimate)

    urlData['URL_NonASCHIIChar'] = URL_ASCHII

    return URL_ASCHII


# 12. Number of digits in URL
def getURL_Digits(urlData):
    URL_Digits = urlData['URLs'].str.count('\d')

    URL_Digits = URL_Digits.apply(lambda x: Fishing if x > 4
                                  else (Legitimate if x <= 2 else Suspicious))
    urlData['URL_DigitsNo'] = URL_Digits

    return URL_Digits

# endregion URL Features
