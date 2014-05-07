#!/usr/local/bin/python2.7
"""Fortiguard URL Rating
Retrieves the Fortiguard Rating for url
Usage:
  get_url_rating2.py (-u <url> | --url <url>)

"""
__author__ = 'olivier'

import requests
from lxml import html
import pprint
from docopt import docopt


def get_fortiguard_rating_for_url(url):
    """
    gets the fortiguard url rating from:
        http://www.fortiguard.com/ip_rep/index.php
        using the ?data=url query
    use a url in form www.google.ch
    returns a string containing the rating
    """
    fortiguardurl = "http://www.fortiguard.com/ip_rep/index.php"
    query = {'data': url}

    page = requests.get(fortiguardurl, params=query)
    tree = html.fromstring(page.text)

    # if you need to asjust the xpath, folow the following structure
    # google chrome -> open website -> inspect element -> right click
    # copy xpath
    rating = tree.xpath('//*[@id="content_wrapper"]/h3/text()')
    return rating


def main():
    """
    main function
    """
    # gets arguments from docopt
    arguments = docopt(__doc__)
    # assigns docopt argument to url
    url = arguments['<url>']
    pprint.pprint(get_fortiguard_rating_for_url(url))

if __name__ == '__main__':
    main()
