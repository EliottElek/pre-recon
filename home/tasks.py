import socket
import subprocess
from celery import shared_task
import logging
import asyncwhois
from home.common import extract_subdomains, get_country_code_from_ip, is_interesting_subdomain
from home.models import IpInfos, Scan, ScanHistory, Subdomain, Target, Whois
from django.utils import timezone
from django.db.utils import IntegrityError

from censys.search import CensysHosts
h = CensysHosts()
OUTPUT_FOLDER = "/output"


@shared_task
def amass(scan_id, target_id, target_ip):
    logging.info(f'Starting AMASS scan on {target_ip}')
    scan = Scan.objects.get(id=scan_id)
    command = f'amass enum -d {target_ip} -timeout 3 -o amass_output_{target_ip}.txt'
    scan_history = ScanHistory(
        scan=scan, name="Amass scan", description=f'Started amass scan for {target_ip}', status="Pending", command=command)
    scan_history.save()
    try:
        logging.info(command)
        subprocess.run(command, shell=True)
        cpt = 0
        with open(f'amass_output_{target_ip}.txt', 'r') as file:
            subdomains = file.readlines()
        for subdomain in subdomains:
            domain = extract_subdomains(target_ip, subdomain.strip())
            if domain:
                try:
                    ip = ""
                    try:
                        ip = socket.gethostbyname(domain)
                    except Exception as e:
                        continue
                    new_subdomain = Subdomain(
                        target_id=target_id, domain_name=domain, source="amass", ip_address=ip, ip_iso=get_country_code_from_ip(ip), is_interesting=is_interesting_subdomain(domain))
                    new_subdomain.save()
                    cpt += 1
                except IntegrityError as e:
                    logging.info(f'Subdomain {domain} already exists.')
                    continue
        scan_history.completed_at = timezone.now()
        scan_history.status = "Finished"
        scan_history.description = f'Found {cpt} new subdomains with amass.'

        scan_history.save()

    except Exception as e:
        logging.error(e)
        scan_history.completed_at = timezone.now()
        scan_history.status = "Error"
        scan_history.description = e
        scan_history.save()


@shared_task
def sublister(scan_id, target_id, target_ip):
    logging.info(f'Starting SUBLISTER scan on {target_ip}')
    scan = Scan.objects.get(id=scan_id)
    command = f'python3 github/Sublist3r/sublist3r.py -d {target_ip}'
    scan_history = ScanHistory(
        scan=scan, name="Sublist3r scan", description=f'Started sublist3r scan for {target_ip}', status="Pending", command=command)
    scan_history.save()
    try:
        logging.info(command)
        process = subprocess.run(command, shell=True,
                                 capture_output=True, text=True)
        scan = Scan.objects.get(id=scan_id)
        cpt = 0

        for subdomain in process.stdout.split('\n'):
            domain = extract_subdomains(target_ip, subdomain.strip())
            if domain:
                try:
                    ip = ""
                    try:
                        ip = socket.gethostbyname(domain)
                    except Exception as e:
                        continue
                    new_subdomain = Subdomain(
                        target_id=target_id, domain_name=domain, source="sublister", ip_address=ip, ip_iso=get_country_code_from_ip(ip), is_interesting=is_interesting_subdomain(domain))
                    new_subdomain.save()
                    cpt += 1
                except IntegrityError as e:
                    logging.info(f'Subdomain {domain} already exists.')
                    continue
        scan_history.completed_at = timezone.now()
        scan_history.status = "Finished"
        scan_history.description = f'Found {cpt} new subdomains with sublister.'
        scan_history.save()
    except Exception as e:
        logging.error(e)
        scan_history.completed_at = timezone.now()
        scan_history.status = "Error"
        scan_history.description = e
        scan_history.save()


@shared_task
def assetfinder(scan_id, target_id, target_ip):
    logging.info(f'Starting ASSETFINDER scan on {target_ip}')
    scan = Scan.objects.get(id=scan_id)
    command = f'docker run assetfinder {target_ip}'
    scan_history = ScanHistory(
        scan=scan, name="Assetfinder scan", description=f'Started assetfinder scan for {target_ip}', status="Pending", command=command)
    scan_history.save()
    try:
        logging.info(command)
        process = subprocess.run(command, shell=True,
                                 capture_output=True, text=True)
        scan = Scan.objects.get(id=scan_id)
        cpt = 0
        for subdomain in process.stdout.split('\n'):
            domain = extract_subdomains(target_ip, subdomain.strip())
            if domain:
                try:
                    ip = ""
                    try:
                        ip = socket.gethostbyname(domain)
                    except Exception as e:
                        continue
                    new_subdomain = Subdomain(
                        target_id=target_id, domain_name=domain, source="assetfinder", ip_address=ip, ip_iso=get_country_code_from_ip(ip), is_interesting=is_interesting_subdomain(domain))
                    new_subdomain.save()
                    cpt += 1
                except IntegrityError as e:
                    logging.info(f'Subdomain {domain} already exists.')
                    continue
        scan_history.completed_at = timezone.now()
        scan_history.status = "Finished"
        scan_history.description = f'Found {cpt} new subdomains with assetfinder.'
        scan_history.save()
    except Exception as e:
        logging.error(e)
        scan_history.completed_at = timezone.now()
        scan_history.status = "Error"
        scan_history.description = e
        scan_history.save()


@shared_task
def subfinder(scan_id, target_id, target_ip):
    scan = Scan.objects.get(id=scan_id)
    command = f'docker run -v $HOME/.config/subfinder:/root/.config/subfinder -t projectdiscovery/subfinder -d {target_ip}'
    scan_history = ScanHistory(
        scan=scan, name="Subfinder scan", description=f'Started subfinder scan for {target_ip}', status="Pending", command=command)
    scan_history.save()
    try:
        logging.info(command)
        process = subprocess.run(command, shell=True,
                                 capture_output=True, text=True)
        scan = Scan.objects.get(id=scan_id)
        cpt = 0
        for subdomain in process.stdout.split('\n'):
            domain = extract_subdomains(target_ip, subdomain.strip())
            if domain:
                try:
                    ip = ""
                    try:
                        ip = socket.gethostbyname(domain)
                    except Exception as e:
                        continue
                    new_subdomain = Subdomain(
                        target_id=target_id, domain_name=domain, source="subfinder", ip_address=ip, ip_iso=get_country_code_from_ip(ip), is_interesting=is_interesting_subdomain(domain))
                    new_subdomain.save()
                    cpt += 1
                except IntegrityError as e:
                    logging.info(f'Subdomain {domain} already exists.')
                    continue

        scan_history.completed_at = timezone.now()
        scan_history.status = "Finished"
        scan_history.description = f'Found {cpt} new subdomains with subfinder.'
        scan_history.save()
    except Exception as e:
        logging.error(e)
        scan_history.completed_at = timezone.now()
        scan_history.status = "Error"
        scan_history.description = e
        scan_history.save()


@shared_task
def censys(target_id):

    target = Target.objects.get(id=target_id)
    try:
        data = h.view(target.ip_address)
        print(data["location"])
        ip_info = IpInfos(
            target=target,
            location_continent=data['location']['continent'],
            location_country=data['location']['country'],
            location_country_code=data['location']['country_code'],
            location_postal_code=data['location']['postal_code'],
            location_timezone=data['location']['timezone'],
            location_latitude=data['location']['coordinates']['latitude'],
            location_longitude=data['location']['coordinates']['longitude'],
            # location_registered_country=data['location']['registered_country'],
            # location_registered_country_code=data['location']['registered_country_code'],
            # location_updated_at=datetime.fromisoformat(
            # data['location_updated_at']),
            # last_updated_at=datetime.fromisoformat(data['last_updated_at'])
        )
        ip_info.save()
    except Exception as e:
        logging.error(e)


@shared_task
def whois(target_id):
    try:
        target = Target.objects.get(id=target_id)
        logging.info(f'Starting WHOIS scan on {target.domain_name}')
        result = asyncwhois.whois_domain(target.domain_name)
        whois = result.parser_output
        if not whois.get('domain_name'):
            raise Exception
    except Exception as e:
        logging.error(e)
        return {
            'status': False,
            'domain': target.domain_name,
            'result': 'Invalid Domain/IP, WHOIS could not be fetched from WHOIS database'
        }
    target = Target.objects.get(id=target_id)
    created = whois.get('created')
    expires = whois.get('expires')
    updated = whois.get('updated')
    registrar = whois.get('registrar')
    dnssec = whois.get('dnssec')
    status = whois.get('status')
    registrant_name = whois.get('registrant_name')
    registrant_organization = whois.get('registrant_organization')
    registrant_address = whois.get('registrant_address')
    registrant_city = whois.get('registrant_city')
    registrant_state = whois.get('registrant_state')
    registrant_zipcode = whois.get('registrant_zipcode')
    registrant_country = whois.get('registrant_country')
    registrant_email = whois.get('registrant_email')
    registrant_phone = whois.get('registrant_phone')
    registrant_fax = whois.get('registrant_fax')
    name_servers = whois.get('name_servers')
    admin_name = whois.get('admin_name')
    admin_id = whois.get('admin_id')
    admin_organization = whois.get('admin_organization')
    admin_city = whois.get('admin_city')
    admin_address = whois.get('admin_address')
    admin_state = whois.get('admin_state')
    admin_zipcode = whois.get('admin_zipcode')
    admin_country = whois.get('admin_country')
    admin_phone = whois.get('admin_phone')
    admin_fax = whois.get('admin_fax')
    admin_email = whois.get('admin_email')
    tech_name = whois.get('tech_name')
    tech_id = whois.get('tech_id')
    tech_organization = whois.get('tech_organization')
    tech_city = whois.get('tech_city')
    tech_address = whois.get('tech_address')
    tech_state = whois.get('tech_state')
    tech_zipcode = whois.get('tech_zipcode')
    tech_country = whois.get('tech_country')
    tech_phone = whois.get('tech_phone')
    tech_fax = whois.get('tech_fax')
    tech_email = whois.get('tech_email')
    target = target
    whois_data = {
        'target': target,
        'created': created,
        'expires': expires,
        'updated': updated,
        'registrar': registrar,
        'dnssec': dnssec,
        'status': status,
        'registrant_name': registrant_name,
        'registrant_organization': registrant_organization,
        'registrant_address': registrant_address,
        'registrant_city': registrant_city,
        'registrant_state': registrant_state,
        'registrant_zipcode': registrant_zipcode,
        'registrant_country': registrant_country,
        'registrant_email': registrant_email,
        'registrant_phone': registrant_phone,
        'registrant_fax': registrant_fax,
        'name_servers': name_servers,
        'admin_name': admin_name,
        'admin_id': admin_id,
        'admin_organization': admin_organization,
        'admin_city': admin_city,
        'admin_address': admin_address,
        'admin_state': admin_state,
        'admin_zipcode': admin_zipcode,
        'admin_country': admin_country,
        'admin_phone': admin_phone,
        'admin_fax': admin_fax,
        'admin_email': admin_email,
        'tech_name': tech_name,
        'tech_id': tech_id,
        'tech_organization': tech_organization,
        'tech_city': tech_city,
        'tech_address': tech_address,
        'tech_state': tech_state,
        'tech_zipcode': tech_zipcode,
        'tech_country': tech_country,
        'tech_phone': tech_phone,
        'tech_fax': tech_fax,
        'tech_email': tech_email
    }

    whois_object = Whois(**whois_data)
    whois_object.save()
