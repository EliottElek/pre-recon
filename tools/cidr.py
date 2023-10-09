import whois


def query_rir_for_keyword(keyword):
    # Define a list of RIRs to query
    rirs = ['whois.ripe.net', 'whois.arin.net', 'whois.apnic.net',
            'whois.lacnic.net', 'whois.afrinic.net']

    # Iterate through the RIRs
    for rir in rirs:
        try:
            w = whois.whois(f'{keyword} {rir}')
            print(f"Results from {rir}:\n{w.text}")
        except Exception as e:
            print(f"Error querying {rir}: {e}")


# Replace 'michelin' with the actual keyword you want to search for
query_rir_for_keyword('michelin.fr')
