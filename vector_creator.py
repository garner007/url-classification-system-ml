"""
 portions of this code come from :
 https://github.com/Anmol-Sharma/URL_CLASSIFICATION_SYSTEM
 https://github.com/P3t3rp4rk3r/MLURL-Machine-Learning-Malicious-URL-Detection/blob/master/mlurl.py

"""


import re
from ipwhois import IPWhois
import socket
import country_converter as coco
from sklearn.feature_extraction.text import CountVectorizer
from entropy import Entropy
import datetime
from datetime import date

# List of Suspicious Words Present in URL
Suspicious_Words = ['secure', 'account', 'update', 'banking', 'login', 'click', 'confirm', 'password', 'verify',
                    'signin', 'ebayisapi', 'lucky', 'bonus', 'pdf', '.exe', '/../', 'base64']

# List of Suspicious Top Level Domains in URLs
Suspicious_TLD = ['zip', 'cricket', 'link', 'work', 'party', 'gq', 'kim', 'country', 'science', 'tk']


# Function to calculate the Total Number of Dots in a URL
def Total_Dots(link):
    dot = '.'
    count = 0
    for i in link:
        if i == dot:
            count += 1
    return count


# Function to calculate the Total Number of Delimeters in a URL
def Total_Delims(url):
    delim = ['-', '_', '?', '=', '&']
    count = 0
    for i in url:
        for j in delim:
            if i == j:
                count += 1
    return count


# Function to calculate the Total Number of Hyphens in a Domain
def no_of_hyphens_in_domain(link):
    hyph = '-'
    count = 0
    for i in link:
        if i == hyph:
            count += 1
    return count


# Function to Check for Presence of Ip in Domain
def ip_presence(lis):
    ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', lis)
    # did we find anything that could resemble an IP address?
    if not ip:
        return 0
    # convert the list from findall into a string
    ip_string = ' '.join(ip)
    # split the string into individual numbers, by the .
    ip_split = ip_string.split('.')
    # check the first octet to be atleast a 1
    if int(ip_split[0]) < 1:
        return 0
    # check each octet to be between 0 and 255
    for number in ip_split:
        try:
            octet = int(number)
            if octet > 255 or octet < 0:
                return 0
            else:
                return 1
        except Exception:
            return 0


# check to see if there is ssl set up for site
def check_https(dom):
    if dom[0:5] == 'https':
        return 1
    else:
        return 0


# get Alexa pagerank
# top 1 million pages from alexa was loaded into a sqlite db, for quick access
def alexa_pagerank(domain, conn):

    cur = conn.cursor()
    cur.execute('SELECT rank from ALEXA_RANK where domain=?', (domain,))
    row = cur.fetchone()
    if row:
        result = 1
    else:
        result = 0
    return int(result)


# lookup IP info
# use socket to get the IP address for the domain
# use IPWHois to retrieve any available WhoIs information
# using unknown if country codes in't returned.

def get_ip_info(dom):

    try:
        ip_address = socket.gethostbyname(dom)
        who_is = IPWhois(ip_address).lookup_rdap()
        # pprint.pprint(who_is)
        country_code = who_is['asn_country_code']
        registration_date = who_is['asn_date']
        date_now = date.today()
        rdate = date(*map(int, registration_date.split('-')))
        difference = date_now - rdate

        if difference > datetime.timedelta(days=365):
            dom_age_gt_1year = 1
        else:
            dom_age_gt_1year = 0

        if country_code == '  ':
            country_name = 'Unknown'
        else:
            # convert the 2char country code into a short name ie US = United States
            country_name = coco.convert(country_code, to='name_short')
            if 'Not' in country_name:
                country_name = 'Unknown'
            else:
                country_name = country_name.replace(" ", "_")

        return country_name, dom_age_gt_1year

    except Exception:
        return 'Unknown', 0


# Bag Of Words method is used for text analysis.
# Here URLs are described by word occurrences while completely
# ignoring the relative position information of the words in
# the document.
# taken  from https://github.com/P3t3rp4rk3r/MLURL-Machine-Learning-Malicious-URL-Detection/blob/master/mlurl.py
def bag_of_words(url):
    vectorizer = CountVectorizer()
    content = re.split('\W+', url)
    X = vectorizer.fit_transform(content)
    num_sample, num_features = X.shape
    return num_features


# Special Characters method to check for specific special
# chars. Sometimes Malicious URLs contain a higher number of
# special characters.
# In this method, a counter is used to count the number of
# special characters that are found within a URL.
# if the counter is > 0, set return to show they were found
# initial code taken from
# https://github.com/P3t3rp4rk3r/MLURL-Machine-Learning-Malicious-URL-Detection/blob/master/mlurl.py
def special_chars(url):
    ctr = 0
    for c in url:
        if c in ['*', ';', '%', '!', '&', ':', '@', '-']:
            ctr += 1
    if ctr > 0:
        return 1
    else:
        return 0


# Defined Vector which will contain the Values for Different Parameters associated with a URL
def Construct_Vector(mystr, conn):
    vec = []

    removed_protocol = re.sub(r'^http(s*)://', '', mystr)  # Removed Protocol in a given URL using Python Regex

    vec.append(len(removed_protocol))  # append length of URL to the Vector
    vec.append(Total_Dots(removed_protocol))  # append Number of Dots in URL to the Vector

    # Checking for Presence of Suspicious Words in URL
    for i in Suspicious_Words:
        if re.search(i, removed_protocol, re.IGNORECASE):
            vec.append(1)  # security sensitive word present so append 1
            break
    else:
        vec.append(0)  # security sensitive word not present so append 0

    patt = r'^[^/]*'  # pattern to extract domain from the URL
    patt_path = r'/[^/]*'  # pattern to extract path of URL
    dom = re.match(patt, removed_protocol).group(0)
    info = re.findall(patt_path, removed_protocol)
    # print('Domain Name: ',dom)
    dom_hyph_count = no_of_hyphens_in_domain(dom)
    vec.append(int(dom_hyph_count))  # Appending Number of hyphens in Domain of URL to the Vector

    domain_tokens = dom.split('.')  # split the domain by the periods
    domain_tokens = [x for x in domain_tokens if x != '']  # Removing Null Values (if Any)
    # print('Domain Length: ',len(dom))

    path_tokens = [re.sub('/', '', x) for x in info]
    if path_tokens != []:
        file_n_args = path_tokens[-1]
    else:
        file_n_args = ''
    path_tokens = path_tokens[:-1]
    info = [x for x in info if x != '']
    slashes = len(info)
    # print('Slashes:',slashes)
    dir_len = 0
    for i in path_tokens:
        dir_len += len(i)
    dir_len += slashes
    vec.append(int(dir_len))  # Appending Directory length to the URL to the Vector
    # print('Directory Length: ',dir_len)

    num_subdir = len(path_tokens)
    # print('Number of Subdirectories :',num_subdir)
    vec.append(num_subdir)  # Appending Number of Subdirectories	Present in the URL to the Vector
    # print('Path Tokens : ',path_tokens)

    TLD = domain_tokens[-1]
    # print('Top Level Domain :',TLD)
    vec.append(len(dom))  # Domain Length
    vec.append(len(domain_tokens))  # Domain Token Count
    vec.append(len(path_tokens))  # Path Token Count

    # does the url contain an IP address
    has_ip = ip_presence(removed_protocol)
    vec.append(has_ip)  # Presence of ip address Yes:1, No:0

    # get the alexa page rank
    has_alexa_rank = alexa_pagerank(dom, conn)
    vec.append(has_alexa_rank)

    # does page use ssl
    uses_https = check_https(mystr)
    vec.append(uses_https)

    # get country code and domain age calc
    country_code, dom_age_gt_1year = get_ip_info(dom)
    vec.append(country_code)

    # domain age gt 1 year
    vec.append(dom_age_gt_1year)

    # bag of words for word occurances
    word = bag_of_words(mystr)
    vec.append(word)

    # entropy of URL
    ent = Entropy(mystr)
    entropy = ent.H(mystr)
    vec.append(entropy)

    # count of special characters
    characters = special_chars(mystr)
    vec.append(characters)

    domain_tok_lengths = []
    for i in domain_tokens:
        domain_tok_lengths.append(len(i))
    largest_dom_token_len = max(domain_tok_lengths)
    vec.append(largest_dom_token_len)  # Largest Domain Token Length

    avg_dom_Tok_len = round((float(sum(domain_tok_lengths)) / len(domain_tok_lengths)),2)

    vec.append(avg_dom_Tok_len)  # Average Domain Token Length

    path_tok_lengths = []
    path_tok_dots = 0
    path_tok_delims = 0
    avg_path_Tok_len = 0
    largest_path_token_len = 0
    if len(path_tokens):
        for i in path_tokens:
            path_tok_lengths.append(len(i))
            path_tok_dots = Total_Dots(i)
            path_tok_delims = Total_Delims(i)
        avg_path_Tok_len = round((float(sum(path_tok_lengths)) / len(path_tok_lengths)), 2)
        largest_path_token_len = max(path_tok_lengths)
        vec.append(largest_path_token_len)  # Largest Path Token Length
        vec.append(avg_path_Tok_len)  # Average Path Token Length
    else:
        vec.append(largest_path_token_len)  # Largest Path Token Length :0 (No, Path Tokens)
        vec.append(avg_path_Tok_len)  # Average Path Token Length :0 (No, Path Tokens)
    # print('Largest Path Token Length:',largest_path_token_len)
    # print('Path Token Total Dots:',path_tok_dots)
    # print('Path Token Delims:',path_tok_delims)
    if has_ip:
        vec.append(0)  # Ip address present so no suspicious TLD
    else:
        for i in Suspicious_TLD:
            if re.search(i, TLD, re.IGNORECASE):
                vec.append(1)  # Suspicious TLD
                break
        else:
            vec.append(0)  # Non Suspicious TLD
    if file_n_args != '':

        # Define Condition whether file and arguments present in the URL
        # POST arguments are conditions passed after the ?
        # file (filenames) are items such as index.html
        tmp = file_n_args.split('?')
        file = tmp[0]
        if len(tmp) > 1:
            args = tmp[1]
        else:
            args = ''
        # print('File:',file)
        # print('Arguments:',args)
        if not file:
            vec.append(0)
        else:
            vec.append(1)
        vec.append(len(file))  # Length of file
        vec.append(Total_Dots(file))  # Total_Dots in file name
        vec.append(Total_Delims(file))  # Total_Delims in file name
        # print('Total dots in file: ',Total_Dots(file))
        # print('Total Delims in file: ',Total_Delims(file))

        if args == '':
            # Checking if any POST arguments present in the URL or not
            vec.append(0)  # no arguments present in url
            vec.append(0)  # Length of Argument Appended to the Vector
            vec.append(0)  # Number of Variables Appended to the Vector
            vec.append(0)  # Length of larges variable value Appended to the Vector
            vec.append(0)  # Maximum number of Delims Appended to the Vector
        # print('argument length:',0)
        # print('number of arguments:',0)
        # print('length of Largest variable value:',0)
        # print('Maximun no of delims:',0)

        else:
            # indicated Presence of POST arguments in the URL
            vec.append(1)  # arguments are present
            vec.append(len(args) + 1)  # Length of Argument Appended to the Vector
            # print('argument length:',len(args)+1)
            arb = args.split('&')
            vec.append(len(arb))  # Number of Arguments Appended to the Vector
            # print('Number of arguments',len(arb))
            len_var = []
            max_delim = []
            for i in arb:
                # Spliting POST Arguments around '=' sign
                tmp = i.split('=')
                if len(tmp) > 1:
                    len_var.append(len(tmp[1]))
                    max_delim.append(Total_Delims(tmp[0]))
                    max_delim.append(Total_Delims(tmp[1]))
                else:
                    len_var.append(0)
                    max_delim.append(0)
            vec.append(max(len_var))  # Length of Largest variable value
            # print('length of Largest variable value:',max(len_var))
            max_delim = max(max_delim)
            vec.append(max_delim)  # Maximum number of Delimeters

        # print('Maximum no of delims:',max_delim)

    else:

        # Defines condition to the corresponding if that File and Arguments are not Present in the URL so
        # Just Append 0 to the corresponding Parameter in the Vector
        vec.append(0)  # has file name in url
        vec.append(0)  # Length of file Appended to the Vector
        vec.append(0)  # Total_Dots in file name Appended to the Vector
        vec.append(0)  # Total_Delims in file name Appended to the Vector
        vec.append(0)  # has arguments appended to url
        vec.append(0)  # Length of Argument Appended to the Vector
        vec.append(0)  # Number of Variables Appended to the Vector
        vec.append(0)  # Length of larges variable value Appended to the Vector
        vec.append(0)  # Maximum number of Delims Appended to the Vector
    # print('argument length:',0)
    # print('number of arguments:',0)

    return vec
