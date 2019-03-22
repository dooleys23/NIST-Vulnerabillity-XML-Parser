from bs4 import BeautifulSoup
import requests, code, json, datetime, os, time

def main():
    if len(os.stat('/root/dooley/nist/cve_monitoring.txt')) == 0:
        get_update()

def get_update():
    # Check each CVE for
    with open('path_to_cve_monitoring.txt') as cve_monitor_file:
        for cve in cve_monitor_file:
            # Setup requests, parsed website
            r = requests.get('https://nvd.nist.gov/vuln/detail/{0}'.format(cve), verify=False)
            soup = BeautifulSoup(r.text, 'html.parser')

            # Date: 1) bs4 soup 2) Put in M/D/Y X:XX:XX A/PM format 3) Make datetime

            change_date = soup.find('span', {'data-testid': 'vuln-change-history-date-0'})
            change_date = str(change_date).split('>')[1].split('<')[0]

            # Month/Day/Year formatting
            mdy = change_date.split(' ', 1)[0]

            month = mdy.split('/')[0]
            # Convert to decimal/0 padded hours
            if len(month) == 1:
                month = '0{}'.format(month)

            day = mdy.split('/')[1]
            # Convert to decimal/0 padded hours
            if len(day) == 1:
                day = '0{}'.format(day)

            year = mdy.split('/')[2]

            # Hour:Minute A/PM
            hmampm = change_date.split(' ', 1)[1]

            hour = hmampm.split(':')[0]
            # Convert to decimal/0 padded hours
            if len(hour) == 1:
                hour = '0{}'.format(hour)

            min = hmampm.split(':')[1]

            am_pm = hmampm.split(' ')[1]

            # Build Change_date into datetime object
            change_date = '{}/{}/{} {}:{} {}'.format(month, day, year, hour, min, am_pm)
            change_date = datetime.datetime.strptime(change_date, '%m/%d/%Y %I:%M %p')

            # Inert if statement to verify that this occured in the last 15sh minutes

            if ((time.time() - change_date)/60) < 15:

            # change_section = soup.find('div',{'id':'p_lt_WebPartZone1_zoneCenter_pageplaceholder_p_lt_WebPartZone1_zoneCenter_VulnerabilityDetail_VulnFormView_VulnChangeHistoryDiv'})
            change_section = soup.find('div', {
                'id': 'p_lt_WebPartZone1_zoneCenter_pageplaceholder_p_lt_WebPartZone1_zoneCenter_VulnerabilityDetail_VulnFormView_VulnChangeHistoryDiv'})

            # HTML of Updated Table
            html = ('<table border="1" class={}'.format((str(change_section).split('<table class=')[1])))


        mailer.sendMail(['to_address@domain'], 'from_address@domain',
                        'NIST Vulnerability Update Detected: {0}'.format(cve), html)


main()
