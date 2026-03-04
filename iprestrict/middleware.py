# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.core import exceptions
from django.conf import settings
import logging
import warnings
from .models import ReloadRulesRequest
from .restrictor import IPRestrictor
from django.core.exceptions import ImproperlyConfigured
try:
    from django.utils.deprecation import MiddlewareMixin
except ImportError:
    class MiddlewareMixin(object):
        def __init__(self, *args, **kwargs):
            pass


logger = logging.getLogger(__name__)


class IPRestrictMiddleware(MiddlewareMixin):
    restrictor = None
    trusted_proxies = None
    allow_proxies = None
    reload_rules = None
    ignore_paths = None

    def __init__(self, *args, **kwargs):
        super(IPRestrictMiddleware, self).__init__(*args, **kwargs)
        self.restrictor = IPRestrictor()
        self.trusted_proxies = tuple(get_setting('IPRESTRICT_TRUSTED_PROXIES', 'TRUSTED_PROXIES', []))
        self.reload_rules = get_reload_rules_setting()
        self.ignore_proxy_header = bool(get_setting('IPRESTRICT_IGNORE_PROXY_HEADER', 'IGNORE_PROXY_HEADER', False))
        self.trust_all_proxies = bool(get_setting('IPRESTRICT_TRUST_ALL_PROXIES', 'TRUST_ALL_PROXIES', False))

        # NEW: exact paths to skip restriction check
        self.ignore_paths = load_ignore_paths()
    def process_request(self, request):
        url = request.path_info

        # NEW: if the request path is whitelisted, skip any iprestrict work (incl. reload_rules DB check)
        if self.is_ignored_path(url):
            return

        if self.reload_rules:
            self.reload_rules_if_needed()

        client_ip = self.extract_client_ip(request)

        if self.restrictor.is_restricted(url, client_ip):
            logger.warn("Denying access of %s to %s" % (url, client_ip))
            raise exceptions.PermissionDenied

    def is_ignored_path(self, url):
        if not self.ignore_paths:
            return False

        # Exact match
        if url in self.ignore_paths:
            return True

        # Optional convenience: treat "/x" and "/x/" as equivalent
        if url.endswith('/'):
            return url[:-1] in self.ignore_paths
        return (url + '/') in self.ignore_paths

    def extract_client_ip(self, request):
        client_ip = request.META['REMOTE_ADDR']
        if not self.ignore_proxy_header:
            forwarded_for = self.get_forwarded_for(request)
            if forwarded_for:
                closest_proxy = client_ip
                client_ip = forwarded_for.pop(0)
                if self.trust_all_proxies:
                    return client_ip
                proxies = [closest_proxy] + forwarded_for
                for proxy in proxies:
                    if proxy not in self.trusted_proxies:
                        logger.warn("Client IP %s forwarded by untrusted proxy %s" % (client_ip, proxy))
                        raise exceptions.PermissionDenied
        return client_ip

    def get_forwarded_for(self, request):
        hdr = request.META.get('HTTP_X_FORWARDED_FOR')
        if hdr is not None:
            return [ip.strip() for ip in hdr.split(',')]
        else:
            return []

    def reload_rules_if_needed(self):
        last_reload_request = ReloadRulesRequest.last_request()
        if last_reload_request is not None:
            if self.restrictor.last_reload < last_reload_request:
                self.restrictor.reload_rules()


def get_setting(new_name, old_name, default=None):
    setting_name = new_name
    if hasattr(settings, old_name):
        setting_name = old_name
        warn_about_changed_setting(old_name, new_name)
    return getattr(settings, setting_name, default)


def get_reload_rules_setting():
    if hasattr(settings, 'DONT_RELOAD_RULES'):
        warn_about_changed_setting('DONT_RELOAD_RULES', 'IPRESTRICT_RELOAD_RULES')
        return not bool(getattr(settings, 'DONT_RELOAD_RULES'))
    return bool(getattr(settings, 'IPRESTRICT_RELOAD_RULES', True))


def warn_about_changed_setting(old_name, new_name):
    warnings.warn(
        "The setting name '%s' has been deprecated and it will be removed in a future version. "
        "Please use '%s' instead." % (old_name, new_name)
    )

def load_ignore_paths():
    """
    NEW:
    Setting: IPRESTRICT_IGNORE_PATHS
    Value: list/tuple of exact request.path_info strings (e.g. "/healthz/" or "/metrics")
    """
    paths = get_setting('IPRESTRICT_IGNORE_PATHS', 'IGNORE_PATHS', [])
    if not paths:
        return set()

    if not isinstance(paths, (list, tuple, set)):
        raise ImproperlyConfigured("IPRESTRICT_IGNORE_PATHS must be a list/tuple/set of path strings")

    cleaned = set()
    for p in paths:
        if not isinstance(p, str):
            raise ImproperlyConfigured("IPRESTRICT_IGNORE_PATHS items must be strings; got %r" % (p,))
        if not p.startswith('/'):
            # enforce Django-like path shape
            p = '/' + p
        cleaned.add(p)

    return cleaned