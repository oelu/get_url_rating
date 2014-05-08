# Get Fortiguard URL Rating
Script to fetch the url rating from www.fortiguard.com

## Requirements
* Requires Python docopt module
* Requires Python lxml module
* Requires Python requests module

## Usage

    Fortiguard URL Rating
        Retrieves the Fortiguard Rating for url
        Usage:
        get_url_rating2.py (-u <url> | --url <url>)

## Example Session

    $ ./get_url_rating.py -u www.github.com
    ['Category: Information Technology']
