import unittest
import mock

import sys
import argparse
import nagiosplugin
from nagiosplugin import CheckError
from nagiosplugin.metric import Metric

from check_dns_sync import check_dns_sync


class Test__query_from_authority(unittest.TestCase):
    result_example_com = [(2017042730, "2001:500:8f::53"),
                          (2017042730, "199.43.135.53"),
                          (2017042730, "199.43.133.53"),
                          (2017042730, "2001:500:8d::53")]

    dig_time_out = "".join(("\n",
                    "; <<>> DiG 9.8.3-P1 <<>> SOA example.com @2.2.2.2\n",
                    ";; global options: +cmd\n",
                    ";; connection timed out; no servers could be reached"))

    dig_example_com = "".join((
        "SOA sns.dns.icann.org. noc.dns.icann.org. 2017042730 7200 3600 1209600 3600 from server 2001:500:8f::53 in 95 ms.\n",
        "SOA sns.dns.icann.org. noc.dns.icann.org. 2017042730 7200 3600 1209600 3600 from server 199.43.135.53 in 97 ms.\n",
        "SOA sns.dns.icann.org. noc.dns.icann.org. 2017042730 7200 3600 1209600 3600 from server 199.43.133.53 in 153 ms.\n",
        "SOA sns.dns.icann.org. noc.dns.icann.org. 2017042730 7200 3600 1209600 3600 from server 2001:500:8d::53 in 160 ms."))


    def test__dig_time_out(self):
        method = check_dns_sync.query_from_authority
        mocked = "check_dns_sync.check_dns_sync.subprocess"
        with mock.patch(mocked) as subprocess:
            stdout = self.dig_time_out
            subprocess.Popen.return_value.communicate.return_value = stdout,stdout
            with self.assertRaises(CheckError):
                method("example.com")

    def test__invalid_zone(self):
        with self.assertRaises(CheckError) as context:
            check_dns_sync.query_from_authority("invalid,domain")

        self.assertTrue("No result. Domain probably does not exist" in str(context.exception))

    def test__dig_reply(self):
        method = check_dns_sync.query_from_authority
        mocked = "check_dns_sync.check_dns_sync.subprocess"
        with mock.patch(mocked) as subprocess:
            stdout = self.dig_example_com
            subprocess.Popen.return_value.communicate.return_value = stdout,stdout
            self.assertEqual(method("example.com"), self.result_example_com)


class Test__query(unittest.TestCase):
    dig_example_com = "sns.dns.icann.org. noc.dns.icann.org. 2017042730 7200 3600 1209600 3600"
    result_example_com = (2017042730, "8.8.8.8")

    def test__invalid_ns(self):
        with self.assertRaises(CheckError) as context:
            check_dns_sync.query("example.com", "invalid,domain")

        self.assertTrue("couldn't get address for 'invalid,domain'" in str(context.exception))

    def test__invalid_zone(self):
        with self.assertRaises(CheckError) as context:
            check_dns_sync.query("invalid,domain", "8.8.8.8")

        self.assertTrue("No result. Domain probably does not exist" in str(context.exception))

    def test__ns_unreachable(self):
        check_dns_sync.parameters = check_dns_sync.parameters + " +time=1 +tries=1"
        with self.assertRaises(CheckError) as context:
            check_dns_sync.query("example.com", "1.1.1.1")

        self.assertTrue("1.1.1.1 timed out" in str(context.exception))

    def test_example_com(self):
        method = check_dns_sync.query
        mocked = "check_dns_sync.check_dns_sync.subprocess"
        with mock.patch(mocked) as subprocess:
            stdout = self.dig_example_com
            stderr = ""
            subprocess.Popen.return_value.communicate.return_value = stdout,stderr
            self.assertEqual(method("example.com", "8.8.8.8"), self.result_example_com)


class Test__CheckDnsSync(unittest.TestCase):
    result_example_com = [(2017042730, "2001:500:8f::53"),
                          (2017042730, "199.43.135.53"),
                          (2017042730, "199.43.133.53"),
                          (2017042730, "2001:500:8d::53")]
    result_not_sync = [(2017042734, "2001:500:8f::53"),
                       (2017042730, "199.43.135.53"),
                       (2017042732, "199.43.133.53"),
                       (2017042734, "2001:500:8d::53")]
    result_ns = (209209, "8.8.8.8")

    def test__probe_from_authority(self):
        check = check_dns_sync.CheckDnsSync("example.com")
        check.fromAuthority = True
        mocked = "check_dns_sync.check_dns_sync.query_from_authority"
        with mock.patch(mocked) as query_from_authority:
            query_from_authority.return_value = self.result_example_com

            for metric,result in zip(check.probe(), self.result_example_com):
                self.assertEqual(type(metric), Metric)
                self.assertEqual(metric.name, result[1])
                self.assertEqual(metric.value, 0)

    def test__probe_not_sync_from_authority(self):
        check = check_dns_sync.CheckDnsSync("example.com")
        check.fromAuthority = True
        mocked = "check_dns_sync.check_dns_sync.query_from_authority"
        with mock.patch(mocked) as query_from_authority:
            query_from_authority.return_value = self.result_not_sync
            probe = check.probe()
            result = next(probe)
            self.assertEqual(result.name, "2001:500:8f::53")
            self.assertEqual(result.value, 0)
            result = next(probe)
            self.assertEqual(result.name, "2001:500:8d::53")
            self.assertEqual(result.value, 0)
            result = next(probe)
            self.assertEqual(result.name, "199.43.133.53")
            self.assertEqual(result.value, 2)
            result = next(probe)
            self.assertEqual(result.name, "199.43.135.53")
            self.assertEqual(result.value, 4)

    def test__probe_from_ns(self):
        check = check_dns_sync.CheckDnsSync("example.com", ["8.8.8.8", "8.8.8.8"])
        check.fromAuthority = False
        mocked = "check_dns_sync.check_dns_sync.query"
        with mock.patch(mocked) as query:
            query.return_value = self.result_ns
            for metric in check.probe():
                self.assertEqual(type(metric), Metric)
                self.assertEqual(metric.name, "8.8.8.8")
                self.assertEqual(metric.value, 0)

    def test__probe_not_sync_from_ns(self):
        check = check_dns_sync.CheckDnsSync("example.com", ["8.8.8.8", "8.8.4.4"])
        check.fromAuthority = False
        mocked = "check_dns_sync.check_dns_sync.query"
        with mock.patch(mocked) as query:
            query.side_effect = [(5, "8.8.8.8"),(10, "8.8.4.4")]
            probe  = check.probe()
            metric = next(probe)
            self.assertEqual(metric.value, 0)
            self.assertEqual(metric.name, "8.8.4.4")
            metric= next(probe)
            self.assertEqual(metric.value, 5)
            self.assertEqual(metric.name, "8.8.8.8")


class Test_AuditSummary(unittest.TestCase):
    """ Stolen from jpcw/checkpkgaudit """
    def test_ok(self):
        from nagiosplugin.result import Result, Results
        from nagiosplugin.state import Ok
        from check_dns_sync.check_dns_sync import AuditSummary
        results = Results()
        ok_r1 = Result(Ok, '', nagiosplugin.Metric('met1', 0))
        ok_r2 = Result(Ok, '', nagiosplugin.Metric('met1', 0))
        results.add(ok_r1)
        results.add(ok_r2)
        summary = AuditSummary(None)
        sum_ok = summary.ok(results)
        self.assertEqual(sum_ok, "All zone are in sync")

    def test_problem_unknown(self):
        from nagiosplugin.result import Result, Results
        from nagiosplugin.state import Critical, Unknown
        from check_dns_sync.check_dns_sync import AuditSummary
        hint = "No result. Domain probably does not exist"
        results = Results()
        r1 = Result(Critical, '', nagiosplugin.Metric('met1', 1))
        r2 = Result(Unknown, hint, nagiosplugin.Metric('met1', 0))
        results.add(r1)
        results.add(r2)
        summary = AuditSummary(None)
        sum_unknown = summary.problem(results)
        self.assertEqual(sum_unknown, hint)

    def test_problem_crit_metric(self):
        from nagiosplugin.result import Result, Results
        from nagiosplugin.state import Critical
        from check_dns_sync.check_dns_sync import AuditSummary
        message = "ns1 1 version behind ns2 1 version behind "
        results = Results()
        r1 = Result(Critical, '', nagiosplugin.Metric('ns1', 1, uom=" version behind"))
        r2 = Result(Critical, '', nagiosplugin.Metric('ns2', 1, uom=" version behind"))
        results.add(r1)
        results.add(r2)
        summary = AuditSummary(True)
        sum_crit = summary.problem(results)
        self.assertEqual(sum_crit, message)

    def test_problem_crit_non_metric(self):
        from nagiosplugin.result import Result, Results
        from nagiosplugin.state import Critical
        from check_dns_sync.check_dns_sync import AuditSummary
        message = "ns1,ns2 are behind"
        results = Results()
        r1 = Result(Critical, '', nagiosplugin.Metric('ns1', 1))
        r2 = Result(Critical, '', nagiosplugin.Metric('ns2', 1))
        results.add(r1)
        results.add(r2)
        summary = AuditSummary(False)
        sum_crit = summary.problem(results)
        self.assertEqual(sum_crit, message)


class Test__parse_arg(unittest.TestCase):
    def test__argparser(self):
        sys.argv = sys.argv[:1]
        sys.argv.append("-z")
        sys.argv.append("localhost")
        args = check_dns_sync.parse_args()
        self.assertEqual(type(args), argparse.Namespace)
        self.assertEqual(args.zone, "localhost")
