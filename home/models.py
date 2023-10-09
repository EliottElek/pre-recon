from django.db import models


class Target(models.Model):
    id = models.AutoField(primary_key=True)
    description = models.CharField(default="", max_length=1000000)
    domain_name = models.CharField(default="", max_length=100)
    ip_address = models.CharField(default="", max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)

    def get_subdomains(self):
        return Subdomain.objects.filter(target=self)

    def __str__(self):
        return self.domain_name


class Whois(models.Model):
    target = models.ForeignKey(
        Target, on_delete=models.CASCADE, related_name='whois_infos', null=True)
    created = models.DateTimeField(null=True, blank=True)
    updated = models.DateTimeField(null=True, blank=True)
    expires = models.DateTimeField(null=True, blank=True)
    registrar = models.CharField(max_length=100, null=True, blank=True)
    registrant_phone = models.CharField(max_length=20, null=True, blank=True)
    registrant_name = models.CharField(max_length=100, null=True, blank=True)
    registrant_organization = models.CharField(
        max_length=100, null=True, blank=True)
    registrant_address = models.CharField(
        max_length=100, null=True, blank=True)
    registrant_city = models.CharField(max_length=50, null=True, blank=True)
    registrant_state = models.CharField(max_length=50, null=True, blank=True)
    registrant_zipcode = models.CharField(max_length=20, null=True, blank=True)
    registrant_country = models.CharField(max_length=50, null=True, blank=True)
    registrant_email = models.EmailField(null=True, blank=True)
    registrant_fax = models.EmailField(null=True, blank=True)
    dnssec = models.CharField(max_length=200, null=True, blank=True)
    status = models.JSONField(max_length=20000, null=True, blank=True)
    name_servers = models.JSONField(max_length=20000, null=True, blank=True)
    admin_name = models.CharField(max_length=100, null=True, blank=True)
    admin_id = models.CharField(max_length=100, null=True, blank=True)
    admin_organization = models.CharField(
        max_length=100, null=True, blank=True)
    admin_city = models.CharField(max_length=50, null=True, blank=True)
    admin_address = models.CharField(max_length=100, null=True, blank=True)
    admin_state = models.CharField(max_length=50, null=True, blank=True)
    admin_zipcode = models.CharField(max_length=20, null=True, blank=True)
    admin_country = models.CharField(max_length=50, null=True, blank=True)
    admin_phone = models.CharField(max_length=20, null=True, blank=True)
    admin_fax = models.CharField(max_length=20, null=True, blank=True)
    admin_email = models.EmailField(null=True, blank=True)
    billing_name = models.CharField(max_length=100, null=True, blank=True)
    billing_id = models.CharField(max_length=100, null=True, blank=True)
    billing_organization = models.CharField(
        max_length=100, null=True, blank=True)
    billing_city = models.CharField(max_length=50, null=True, blank=True)
    billing_address = models.CharField(max_length=100, null=True, blank=True)
    billing_state = models.CharField(max_length=50, null=True, blank=True)
    billing_zipcode = models.CharField(max_length=20, null=True, blank=True)
    billing_country = models.CharField(max_length=50, null=True, blank=True)
    billing_phone = models.CharField(max_length=20, null=True, blank=True)
    billing_fax = models.CharField(max_length=20, null=True, blank=True)
    billing_email = models.EmailField(null=True, blank=True)
    tech_name = models.CharField(max_length=100, null=True, blank=True)
    tech_id = models.CharField(max_length=100, null=True, blank=True)
    tech_organization = models.CharField(max_length=100, null=True, blank=True)
    tech_city = models.CharField(max_length=50, null=True, blank=True)
    tech_address = models.CharField(max_length=100, null=True, blank=True)
    tech_state = models.CharField(max_length=50, null=True, blank=True)
    tech_zipcode = models.CharField(max_length=20, null=True, blank=True)
    tech_country = models.CharField(max_length=50, null=True, blank=True)
    tech_phone = models.CharField(max_length=20, null=True, blank=True)
    tech_fax = models.CharField(max_length=20, null=True, blank=True)
    tech_email = models.EmailField(null=True, blank=True)


class IpInfos(models.Model):
    target = models.ForeignKey(
        Target, on_delete=models.CASCADE, related_name='ip_infos', null=True)
    location_continent = models.CharField(max_length=100, null=True)
    location_country = models.CharField(max_length=100, null=True)
    location_country_code = models.CharField(max_length=2, null=True)
    location_postal_code = models.CharField(max_length=20, blank=True)
    location_timezone = models.CharField(max_length=100, null=True)
    location_latitude = models.FloatField(null=True)
    location_longitude = models.FloatField(null=True)
    location_registered_country = models.CharField(max_length=100, null=True)
    location_registered_country_code = models.CharField(
        max_length=2, null=True)
    location_updated_at = models.DateTimeField(null=True)
    last_updated_at = models.DateTimeField(null=True)

    def __str__(self):
        return self.location_country


class Scan(models.Model):
    id = models.AutoField(primary_key=True)
    description = models.CharField(default="", max_length=1000000)
    target = models.ForeignKey(Target, on_delete=models.CASCADE)
    certfinder = models.CharField(default="", max_length=1000000)
    nuclei = models.CharField(default="", max_length=1000000)
    subfinder = models.CharField(default="", max_length=1000000)
    status = models.CharField(default="Pending", max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    progress = models.IntegerField(default=0)

    def update_status(self):
        # Get all associated ScanHistory objects
        scan_histories = ScanHistory.objects.filter(
            scan_id=self.id).order_by("-started_at")

        finished_count = sum(
            1 for history in scan_histories if history.status == 'Finished')
        error_count = sum(
            1 for history in scan_histories if history.status == 'Error')
        pending_count = sum(
            1 for history in scan_histories if history.status == 'Pending')

        if error_count + finished_count == len(scan_histories):
            self.progress = 100  # All tasks are finished or in error
            self.status = 'Finished'
        else:
            if error_count > 0:
                self.status = 'Error'
            elif finished_count == len(scan_histories):
                self.status = 'Finished'
            elif pending_count > 0:
                self.status = 'Pending'
            else:
                self.status = 'Other'

            if pending_count > 0:
                self.progress = int(
                    100 - pending_count / (finished_count + error_count + pending_count) * 100)
            else:
                self.progress = 0

        self.save()


class Subdomain(models.Model):
    id = models.AutoField(primary_key=True)
    target = models.ForeignKey(
        Target, on_delete=models.CASCADE, related_name='subdomains')
    ip_address = models.CharField(default="", max_length=1000)
    domain_name = models.CharField(default="", max_length=1000, unique=True)
    source = models.CharField(default="", max_length=100, null=True)
    found_at = models.DateTimeField(auto_now_add=True)
    ip_iso = models.CharField(max_length=2, null=True)
    is_interesting = models.BooleanField(default=False)


class ScanHistory(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=400)
    status = models.CharField(max_length=100, null=True)
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(auto_now_add=False, null=True)
    command = models.CharField(max_length=1000)

    def get_finished_in(self):
        if not self.completed_at:
            started_time = self.started_at.strftime(
                '%H:%M')  # Format hours and minutes
            return f'Started at {started_time}'

        # Calculate the difference
        difference = self.completed_at - self.started_at

        # Extract hours, minutes, and seconds
        minutes = (difference.seconds % 3600) // 60
        seconds = difference.seconds % 60

        return f"Finished in {minutes}min{seconds}s"
