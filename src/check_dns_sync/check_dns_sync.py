#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Check that DNS servers are at the same update
"""
import nagiosplugin

import subprocess
import argparse

executable = "dig"
parameters_from_authority = "+nssearch"
parameters = "+short"


def query_from_authority(zone):
    """Send query using external tool to fetch serial from NS servers of the zone"""
    proc = subprocess.Popen([executable, zone]+parameters_from_authority.split(),
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)
    answers,error = proc.communicate()
    if not isinstance(answers, str):  # pragma: no cover
        answers = answers.decode()
    if not isinstance(error, str):  # pragma: no cover
        error = error.decode()

    if answers.find("timed out") >= 0:
        raise nagiosplugin.CheckError("A server timed out")
    if not len(answers):
        raise nagiosplugin.CheckError("No result. Domain probably does not exist")

    answers = answers.split('\n')
    returned_answer = []
    for answer in answers:
        if len(answer) > 0:
            if not 'SOA ' in answer:
                raise nagiosplugin.CheckError(f"No parsable SOA: {answer}")
            else:
                answer = answer.split()
                returned_answer.append((int(answer[3]), answer[10]))
    return returned_answer


def query(zone, nameserver):
    """Send query using external tool to fetch serial from provided server"""
    query = "{0} SOA @{1}".format(zone, nameserver)
    proc = subprocess.Popen([executable, zone, 'SOA', '@'+nameserver] + parameters.split(),
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)
    answer,error = proc.communicate()
    if not isinstance(answer, str):  # pragma: no cover
        answer = answer.decode()
    if not isinstance(error, str):  # pragma: no cover
        error = error.decode()

    if answer.find("timed out") >= 0:
        raise nagiosplugin.CheckError("%s timed out" % nameserver)
    if error:
        raise nagiosplugin.CheckError("Dig returned an error: %s" % error)
    if not len(answer):
        raise nagiosplugin.CheckError("No result. Domain probably does not exist")

    return (int(answer.split()[2]), nameserver)


class CheckDnsSync(nagiosplugin.Resource):
    """Check nameserver syncronisation plugin"""
    def __init__(self, zone, nameservers=[], fromAuthority=True):
        self.zone = zone
        self.fromAuthority = fromAuthority
        self.nameservers = nameservers

    def probe(self):
        """Get serial of servers using asked method"""
        if self.fromAuthority:
            serials = query_from_authority(self.zone)
        else:
            serials = [query(self.zone, nameserver) for nameserver in self.nameservers]

        serials.sort(reverse=True)
        for serial, server in serials:
            deltaSerial = serials[0][0] - serial
            yield nagiosplugin.Metric(server,
                                      deltaSerial,
                                      min=0,
                                      context="serial",
                                      uom=" version behind")


class AuditSummary(nagiosplugin.Summary):
    """docstring for AuditSummary."""
    def __init__(self, displayMetrics):
        self.displayMetrics = displayMetrics

    def ok(self, results):
        return "All zone are in sync"

    def problem(self, results):
        if results.most_significant_state.code == 3:
            return results.first_significant.hint
        else:
            if self.displayMetrics:
                message = ''
                for result in results.most_significant:
                    message = message + (result.metric.name+" "
                                         + str(result.metric.value)
                                         + result.metric.uom+" ")
            else:
                message = ','
                message = message.join(sorted((result.metric.name for result
                                               in results.most_significant)))
                message = message + " are behind"

            return message


def parse_args():
    argp = argparse.ArgumentParser(description=__doc__)
    argp.add_argument('-v', '--verbose', action='count', default=0,
                      help='increase output verbosity (use up to 3 times)')
    argp.add_argument('-z', '--zone', help='address of zone to test', required=True)
    argp.add_argument('--use-ns', dest="fromAuthority", action="store_true",
                      help="Query the ns from the zone's authority (NS field)")
    argp.add_argument('--no-use-ns', dest="fromAuthority", action="store_false")
    argp.set_defaults(fromAuthority=True)
    argp.add_argument('-ns', '--nameservers', nargs='*', default=[],
                      help="Specify the ns to query to")
    argp.add_argument('-m', '--metric', help="Display how many version behind", action="store_true")
    return argp.parse_args()


@nagiosplugin.guarded
def main(): # pragma: no cover
    args = parse_args()
    check = nagiosplugin.Check(CheckDnsSync(args.zone, args.nameservers, args.fromAuthority),
                               nagiosplugin.ScalarContext("serial", None, '@1:'),
                               AuditSummary(args.metric))
    check.main()


if __name__ == '__main__': # pragma: no cover
    main()
