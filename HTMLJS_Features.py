from urllib.request import urlopen
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from multiprocessing.pool import ThreadPool

Legitimate = 0
Fishing = 1
Suspicious = -1


def getHTMLJS_Features(url):
    try:
        result = 0
        html = urlopen(url, timeout=(3)).read()
        soup = BeautifulSoup(html, features="html.parser", from_encoding="iso-8859-1")
        total = 0
        counter = 0

        ownDomain = urlparse(url)
        ownDomain = ownDomain.netloc
        ownDomain = ownDomain.replace('www.', '')

        # get text
        text = soup.get_text()
        for link in soup.find_all('a'):
            link = link.get('href')

            Domain = urlparse(link)
            Domain = Domain.netloc

            if Domain != '':
                if 'www.' in Domain:
                    DomainName = Domain.replace('www.', '')
                    total = total + 1
                    if DomainName == ownDomain:
                        counter = counter + 1
                else:
                    counter = 0

        repetitionPercentage = (counter / total) * 100

        # Disabled right click
        # iframe
        script = soup.find_all(lambda tag: tag.name == 'script')

        iframe = soup.find_all(lambda tag: tag.name == 'iframe' or tag.name == 'frameBorder')
        # Number of web forwards
        webForwards = soup.find_all(r"history.length")

        # Window popup exists
        popupWindow = soup.find_all(r"window.open")

        # break into lines and remove leading and trailing space on each
        lines = (line.strip() for line in text.splitlines())
        # break multi-headlines into a line each
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        # drop blank lines
        text = '\n'.join(chunk for chunk in chunks if chunk)

        # First if as a joke to lighten up the mood
        if text.__contains__(r'Winner of 10000'):
            result = Fishing

        # onMouseOver event
        elif r'.+onmouseover.+' in str(script):
            result = Fishing

        # iframe
        elif r'aria-hidden="true"' or r'style="display:none;visibility:hidden"' in str(iframe) or str(iframe) == r'[]':
            result = Fishing

        # Right click disabled
        elif not (r"event.button ?== ?2" in str(script)):
            result = Fishing

        # Web forwards
        elif webForwards <= 3:
            result = Fishing

        # Popup window
        elif str(popupWindow) == '[]':
            result = Fishing

        elif repetitionPercentage <= 40:
            result = Fishing

        else:
            result = Legitimate

    except:
        result = Legitimate

    return result  # -1, 0 , 1


def HTMLJS_FeaturesThreading(urlData):
    threadPool = ThreadPool(100)
    output = threadPool.map(getHTMLJS_Features, urlData['URLs'])
    urlData['HTMLJS_Features'] = output
    # print(len(output))
    return output
