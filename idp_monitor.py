#!/usr/bin/env python

import argparse
import cookielib
import importlib
import sys
import time

from urlparse import parse_qs

from saml2.client import Saml2Client
from saml2.config import SPConfig, logging
from saml2.s_utils import rndstr
from saml2.samlp import STATUS_SUCCESS

from interaction import Interaction, Discovery
from interaction import InteractionNeeded
from interaction import Action

logger = logging.getLogger("saml2.idp_monitor")

__author__ = 'roland'


class Check(object):
    def __init__(self, client, interaction_spec):
        self.client = client
        self.cjar = {"browser": cookielib.CookieJar(),
                     "rp": cookielib.CookieJar(),
                     "service": cookielib.CookieJar()}
        self.interaction = Interaction(self.client, interaction_spec)
        self.features = None
        self.login_time = 0

    def my_endpoints(self):
        """
        :returns: All the assertion consumer service endpoints this
            SP publishes.
        """
        return [e for e, b in self.client.config.getattr("endpoints", "sp")[
            "assertion_consumer_service"]]

    def intermit(self, response):
        """
        This method is supposed to handle all needed interactions.
        It also deals with redirects.

        :param response: A response from the IdP
        """
        _response = response
        _last_action = None
        _same_actions = 0
        if _response.status_code >= 400:
            done = True
        else:
            done = False

        url = _response.url
        content = _response.text
        while not done:
            rdseq = []
            while _response.status_code in [302, 301, 303]:
                url = _response.headers["location"]
                if url in rdseq:
                    print >> sys.stderr, "URL: %s" % url
                    print >> sys.stderr, content
                    raise Exception("Loop detected in redirects")
                else:
                    rdseq.append(url)
                    if len(rdseq) > 8:
                        raise Exception(
                            "Too long sequence of redirects: %s" % rdseq)

                # If back to me
                for_me = False
                for redirect_uri in self.my_endpoints():
                    if url.startswith(redirect_uri):
                        # Back at the RP
                        self.client.cookiejar = self.cjar["rp"]
                        for_me = True
                        try:
                            base, query = url.split("?")
                        except ValueError:
                            pass
                        else:
                            _response = parse_qs(query)
                            return _response

                if for_me:
                    done = True
                    break
                else:
                    _response = self.client.send(url, "GET")

                    if _response.status_code >= 400:
                        done = True
                        break

            if done or url is None:
                break

            _base = url.split("?")[0]

            try:
                _spec = self.interaction.pick_interaction(_base, content)
            except InteractionNeeded:
                cnt = content.replace("\n", '').replace("\t", '').replace("\r",
                                                                          '')
                raise Exception(cnt)
            except KeyError:
                cnt = content.replace("\n", '').replace("\t", '').replace("\r",
                                                                          '')
                raise Exception(cnt)

            if _spec == _last_action:
                _same_actions += 1
                if _same_actions >= 3:
                    print >> sys.stderr, "URL: %s" % url
                    print >> sys.stderr, content
                    raise Exception("Interaction loop detection")
            else:
                _last_action = _spec

            try:
                page_type = _spec["page-type"]
            except KeyError:
                page_type = ""
            else:
                if page_type == "login":
                    login_start = time.time()

            if page_type == "discovery":
                _op = Discovery(_spec["control"])
            else:
                _op = Action(_spec["control"])

            try:
                _response = _op(self.client, self, url, _response)
                if page_type == "login":
                    self.login_time = time.time() - login_start

                if isinstance(_response, dict):
                    return _response
                content = _response.text

                if _response.status_code >= 400:
                    txt = "Got status code '%s', error: %s" % (
                        _response.status_code, content)
                    raise Exception(txt)
            except InteractionNeeded:
                raise
            except Exception:
                raise


NAGIOS_LINE = "[{time}] PROCESS_SERVICE_CHECK_RESULT;{host};{svc};{code};{" \
              "output}"

RETURN_CODE = {"OK": 0, "WARNING": 1, "CRITICAL": 2, "UNKNOWN": 3}


def check(client, conf, entity_id, suppress_output=False, login_time=False,
          nagios=False, nagios_args=None):

    check = Check(client, conf.INTERACTION)

    _client = check.client
    relay_state = rndstr()
    _id, htargs = _client.prepare_for_authenticate(entity_id,
                                                   relay_state=relay_state)
    resp = _client.send(htargs["headers"][0][1], "GET")

    if resp.status_code >= 400:
        print "Error"
        print >> sys.stderr, resp.text

    # resp should be dictionary with keys RelayState, SAMLResponse and endpoint
    try:
        resp = check.intermit(resp)
    except Exception, err:
        print "Error"
        print "%s" % err
    else:
        if resp is None:
            print "Error"
        else:
            serv, binding = _client.config.endpoint2service(resp["endpoint"])

            resp = _client.parse_authn_request_response(resp["SAMLResponse"],
                                                        binding)
            assert resp.in_response_to == _id
            try:
                assert resp.response.status.status_code.value == STATUS_SUCCESS
            except AssertionError:
                # Got an error response
                if nagios:
                    _kwargs = {
                        "time": time.time(),
                        "code": RETURN_CODE["CRITICAL"],
                        "output": resp.response.status
                    }
                    _kwargs.update(nagios_args)
                    print NAGIOS_LINE.format(**_kwargs)
                else:
                    print "Error"
                    print >> sys.stderr, resp.response.status
            else:
                if nagios:
                    _kwargs = {
                        "time": time.time(),
                        "code": RETURN_CODE["OK"],
                        "output": ""
                    }
                    _kwargs.update(nagios_args)
                    print NAGIOS_LINE.format(**_kwargs)
                elif not suppress_output:
                    if login_time:
                        print "OK %s" % check.login_time
                    else:
                        print "OK"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', dest='conf_path')
    parser.add_argument('-e', dest='entity_id')
    parser.add_argument('-t', dest='login_split_time', action='store_true')
    parser.add_argument('-n', dest='count', default="1")
    parser.add_argument(
        '-N', dest='nagios', action='store_true',
        help="If Nagios Passive Service Check Results output should be used")
    parser.add_argument('-S', dest='svc',
                        help="Service description for Nagios output")
    parser.add_argument('-H', dest='host',
                        help="Service host for Nagios output")
    parser.add_argument(dest="config")
    args = parser.parse_args()

    #print args
    sys.path.insert(0, ".")
    # If a specific configuration directory is specified look there first
    if args.conf_path:
        sys.path.insert(0, args.conf_path)
    conf = importlib.import_module(args.config)
    sp_config = SPConfig().load(conf.CONFIG, metadata_construction=False)

    client = Saml2Client(sp_config)

    if not args.entity_id:
        # check if there is only one in the metadata store
        entids = client.metadata.items()
        # entids is list of 2-tuples (entity_id, entity description)
        if len(entids) == 1:
            entity_id = entids[0][0]
        else:
            entity_id = args.entity_id
    else:
        entity_id = args.entity_id
        assert client.metadata[entity_id]

    if args.nagios:
        try:
            assert args.count == "1"
            assert args.login_split_time is False
        except AssertionError:
            print "you can't combine -N with -n and -t flags"
            return
        nagios_args = {"host": args.host, "svc": args.svc}
    else:
        nagios_args = {}

    if args.count == "1":
        check(client, conf, entity_id, login_time=args.login_split_time,
              nagios=args.nagios, nagios_args=nagios_args)
    else:
        for i in range(0, int(args.count)):
            check(client, conf, entity_id, suppress_output=True,
                  nagios_args=nagios_args)


if __name__ == "__main__":
    #start = time.time()
    main()
    #print time.time() - start