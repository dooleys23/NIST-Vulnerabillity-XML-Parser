# SD. Works using 3 seperate files in same directory.
# 1) main.py 
# 2) rss_whitelist.txt - list of words to monitor for, newline per word
# 3) cve_history.txt - list of positive historical CVE's detected

import feedparser, time, mailer, datetime, dateutil, code

white_word_list = []
known_cve_list = []

# Create dictionaries 1) NIST website 2) White words to search for Vulns. 3) All known CVE's
d = feedparser.parse('https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml')

for word in open('path_to_rss_whitelist.txt','r'):  # Read each vuln. word and add it to list
    word = word.lower()
    white_word_list.append(word)

with open('path_to_cve_history.txt','r') as cve_file:  # Read each previously affected cve, add to list    
    for cve in cve_file:
        if len(cve.strip()) != 0:
            known_cve_list.append(cve)

# Email string to be sent out with bad CVE's, to be deleted after verified working
wrekt = ''
new_cve_count = 0

# Get every CVE Index key, dic
for entry in range(len(d['entries'])):
    # Split description into word list
    description_list = d['entries'][entry]['description'].lower().split()
    # For every word in the Vulnerabillity list
    for white_word in white_word_list:
        # Ensure clean word
        white_word = white_word.strip()
        for description_word in description_list:
            # If the White List Word == CVE description word
            if white_word == description_word:
                #  Set variables
                match_word = white_word
                cve = d['entries'][entry]['title'].split(' ', 1)[0].lower()
                title = d['entries'][entry]['title'].split(' ', 1)[1]
                description = d['entries'][entry]['summary_detail']['value']
                url = d['entries'][entry]['link']
                date = time.strptime(d['entries'][entry]['date'].strip('Z'), '%Y-%m-%dT%H:%M:%S')
                cve_epoch = int(datetime.datetime.fromtimestamp(time.mktime(date)).strftime('%s'))

                # Check if CVE Created within the last 15 minutes
                if ((time.time() - cve_epoch)/60) < 9000:

                    # Checks if cve already in known database. If it is, add to wrekt list, or just continue
                    if any(cve in s for s in known_cve_list):
                        continue

                    # New CVE determined, CVE was not found in already known list
                    else:
                            # HTML body
                            today = datetime.date.today()

                            # Add CVE to known CVE List, increase CVE tally
                            known_cve_list.append(cve.strip())
                            new_cve_count += 1

                            html = ('<html> <head> <style> table, th, td {{ border: 1px solid black; }} </style> </head>'
                                    ' <body> <table style="width:100%"> <tr> <th style="width:10%">CVE</th>'
                                    ' <th style="width:20%">Title</th> <th style="width:70%">Description</th><th>Matched word</th></tr> <tr> '
                                    '<td><a href="{0}">{1}</a></td> <td>{2}</td> <td>{3}</td> <td><b>{4}</td> </tr> </table> <br></body> '
                                    '</html><br> Generated on {5}'.format(url, cve, title, description, white_word, today))

                            # Custom written mailer, google how to mail in email markup
                            mailer.sendMail(['to_address@domain'], 'from_address@domain' ,
                                            'NIST Vulnerability detected: {0}: {1}'.format(cve, title), html)

                else:
                    wrekt += '{0}, {1}, {2}, {3}, {4} <br>'.format(((time.time() - cve_epoch) / 60), time.time(), cve_epoch,
                                                               title, cve)

# If no new CVE's are discovered, send out debug email. To be removed later
if new_cve_count == 0:
    mailer.sendMail(['to_addr@domain'], 'from_addr@domain' , 'No NIST Vulnerability detected', wrekt)

# Write out known affected CVE's for historical purposes
with open('/root/dooley/nist/cve_history.txt','w+') as cve_history:
    for known_cve in known_cve_list:
        cve_history.write('{0}\n'.format(known_cve))
