from ipaddress import ip_address
from django.shortcuts import render, redirect, get_object_or_404
from datetime import datetime
from .models import *
from .forms import DeleteScansForm, ScanForm, TargetForm
from .tasks import amass, assetfinder, censys, subfinder, sublister, whois
import socket
from django.core.exceptions import ObjectDoesNotExist


def convert_datetime_to_iso(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj


def index(request):

    scans = Scan.objects.order_by("-created_at")
    for scan in scans:
        scan.update_status()
    context = {
        'segment': 'index',
        'scans': scans,
        'scans_length': len(Scan.objects.all()),
        'targets': Target.objects.order_by("-created_at").prefetch_related('subdomains'),
        'targets_length': len(Target.objects.all()),
    }
    # Scan.objects.all().delete()
    # Target.objects.all().delete()

    return render(request, "index.html", context)


def scan_details(request, scan_id):
    scan = get_object_or_404(Scan, pk=scan_id)
    target = get_object_or_404(Target, pk=scan.target.id)
    subdomains = Subdomain.objects.filter(
        target_id=target.id).order_by("-found_at")
    history = ScanHistory.objects.filter(
        scan_id=scan.id).order_by("-started_at")
    try:
        whoisInfos = Whois.objects.get(pk=target.id) or None
    except ObjectDoesNotExist:
        whoisInfos = None

    return render(request, "scans/index.html", {"scan": scan, "whois": whoisInfos, "subdomains": subdomains, "history": history})


def target_details(request, target_id):
    target = get_object_or_404(Target, pk=target_id)
    scans = Scan.objects.filter(target_id=target.id)
    ip_infos = IpInfos.objects.get(pk=target_id)
    whoisInfos = None
    try:
        whoisInfos = Whois.objects.get(pk=target_id) or None
    except ObjectDoesNotExist:
        whoisInfos = None

    subdomains = Subdomain.objects.filter(
        target_id=target_id).order_by("-found_at")
    return render(request, "targets/index.html", {"target": target, "scans": scans, "whois": whoisInfos, "subdomains": subdomains, "ip_infos": ip_infos})


def starter(request):
    context = {}
    return render(request, "starter.html", context)


def new_target(request):
    if request.method == 'POST':
        form = TargetForm(request.POST)
        if form.is_valid():
            description = request.POST.get('description')
            domain_name = request.POST.get('domain_name')
            target = Target(description=description, domain_name=domain_name,
                            ip_address=socket.gethostbyname(domain_name))
            target.save()
            whois.apply_async(args=[
                target.id
            ])
            censys.apply_async(args=[
                target.id
            ])
            return redirect("/")
    else:
        form = TargetForm()

    return render(request, 'new-target.html', {'form': form})


def new_scan(request):
    if request.method == 'POST':
        form = ScanForm(request.POST)
        if form.is_valid():
            description = request.POST.get('description')
            related_target_id = request.POST.get('target')
            target = Target.objects.get(id=related_target_id)
            scan = Scan(description=description, target=target)
            scan.save()
            scan_history = ScanHistory(
                scan=scan, name="Initiate new scan", status="Starting", description=f'Started new scan for {target.ip_address}')
            scan_history.save()

            subfinder.apply_async(args=[
                scan.id, target.id, target.domain_name
            ])
            sublister.apply_async(args=[
                scan.id, target.id, target.domain_name
            ])
            amass.apply_async(args=[
                scan.id, target.id, target.domain_name
            ])
            assetfinder.apply_async(args=[
                scan.id, target.id, target.domain_name
            ])
            scan_history.status = "Finished"
            scan_history.save()
            return redirect("/")

    else:
        form = ScanForm()
    return render(request, 'new-scan.html', {'form': form})


def delete_scans(request):
    if request.method == 'POST':
        form = DeleteScansForm(request.POST)
        if form.is_valid():
            # ids = request.POST.getlist('ids[]')
            # Scan.objects.filter(id__in=ids).delete()
            Scan.objects.all().delete()
            return redirect('/')  # Replace with your actual view name
    else:
        form = DeleteScansForm()
    return render(request, 'new-scan.html', {'form': form})
