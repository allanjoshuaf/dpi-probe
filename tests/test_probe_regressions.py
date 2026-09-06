from src.probes import bypass_test, dns_test


def test_numeric_sni_case_randomization_terminates():
    assert bypass_test.randomize_case('123.456') == '123.456'
    assert bypass_test.randomize_case('example.test') != 'example.test'


def test_failed_reference_resolvers_are_not_consistent():
    result = dns_test.classify({'status': 'ok', 'ips': ['1.1.1.1']}, [{'status': 'timeout', 'ips': []}])
    assert result == ('inconclusive', ['no_reference_answers'])
