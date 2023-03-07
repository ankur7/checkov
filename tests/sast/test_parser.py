from checkov.sast.checks_infra.checks_parser import SastCheckParser


def test_metadata_parsing():
    raw_check = {
        'metadata': {
            'id': 'CKV_SAST_1',
            'name': 'check name',
            'guidelines': 'some guidelines',
            'category': 'sast',
            'cwe': 'CWE-289: Authentication Bypass by Alternate Name',
            'owasp': 'OWASP 1: some owasp',
            'severity': 'LOW'
        },
        'scope': {
            'languages': ['python']
        },
        'definition': [
            {'cond_type': 'pattern', 'operator': 'equals', 'value': 'set_port($ARG)'}
        ]
    }
    parser = SastCheckParser()
    parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
    assert parsed_check == {
        'id': 'CKV_SAST_1',
        'message': 'some guidelines',
        'severity': 'INFO',
        'languages': ['python'],
        'metadata': {
            'name': 'check name',
            'cwe': 'CWE-289: Authentication Bypass by Alternate Name',
            'owasp': 'OWASP 1: some owasp'
        },
        'pattern': 'set_port($ARG)'
    }


def test_multiline_pattern_parsing():
    raw_check = {
        'metadata': {'id': 'CKV_SAST_1', 'name': 'check name', 'guidelines': 'some guidelines', 'category': 'sast',
            'severity': 'LOW'}, 'scope': {'languages': ['python']},
        'definition': [
            {'cond_type': 'pattern', 'operator': 'equals', 'value': 'def $FUNC(...):\n  ...\n'},
        ]
    }
    parser = SastCheckParser()
    parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
    assert parsed_check == {
        'id': 'CKV_SAST_1',
        'message': 'some guidelines',
        'severity': 'INFO',
        'languages': ['python'],
        'metadata': {
            'name': 'check name'
        },
        'pattern': 'def $FUNC(...):\n  ...\n'
    }


def test_pattern_not_parsing():
    raw_check = {
        'metadata': {'id': 'CKV_SAST_1', 'name': 'check name', 'guidelines': 'some guidelines', 'category': 'sast',
            'severity': 'LOW'}, 'scope': {'languages': ['python']},
        'definition': [
            {'cond_type': 'pattern', 'operator': 'not_equals', 'value': 'set_port($ARG)'},
        ]
    }
    parser = SastCheckParser()
    parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
    assert parsed_check == {
        'id': 'CKV_SAST_1',
        'message': 'some guidelines',
        'severity': 'INFO',
        'languages': ['python'],
        'metadata': {
            'name': 'check name'
        },
        'pattern-not': 'set_port($ARG)'
    }


def test_pattern_either_parsing():
    raw_check = {
        'metadata': {'id': 'CKV_SAST_1', 'name': 'check name', 'guidelines': 'some guidelines', 'category': 'sast',
            'severity': 'LOW'}, 'scope': {'languages': ['python']},
        'definition': [
            {
                'or': [
                    {'cond_type': 'pattern', 'operator': 'equals', 'value': 'set_port_1($ARG)'},
                    {'cond_type': 'pattern', 'operator': 'equals', 'value': 'set_port_2($ARG)'}
                ]
            }
        ]
    }
    parser = SastCheckParser()
    parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
    assert parsed_check == {
        'id': 'CKV_SAST_1',
        'message': 'some guidelines',
        'severity': 'INFO',
        'languages': ['python'],
        'metadata': {
            'name': 'check name'
        },
        'pattern-either': [
            {'pattern': 'set_port_1($ARG)'},
            {'pattern': 'set_port_2($ARG)'}
        ]
    }


def test_explicit_patterns_parsing():
    raw_check = {
        'metadata': {'id': 'CKV_SAST_1', 'name': 'check name', 'guidelines': 'some guidelines', 'category': 'sast',
            'severity': 'LOW'}, 'scope': {'languages': ['python']},
        'definition': [
            {
                'and': [
                    {'cond_type': 'pattern', 'operator': 'equals', 'value': 'set_port_1($ARG)'},
                    {'cond_type': 'pattern', 'operator': 'equals', 'value': 'set_port_2($ARG)'}
                ]
            }
        ]
    }
    parser = SastCheckParser()
    parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
    assert parsed_check == {
        'id': 'CKV_SAST_1', 'message': 'some guidelines', 'severity': 'INFO', 'languages': ['python'], 'metadata': {
            'name': 'check name'},
        'patterns': [
            {'pattern': 'set_port_1($ARG)'},
            {'pattern': 'set_port_2($ARG)'}
        ]
    }


def test_implicit_patterns_parsing():
    raw_check = {
        'metadata': {'id': 'CKV_SAST_1', 'name': 'check name', 'guidelines': 'some guidelines', 'category': 'sast',
            'severity': 'LOW'}, 'scope': {'languages': ['python']},
        'definition': [
            {'cond_type': 'pattern', 'operator': 'equals', 'value': 'set_port_1($ARG)'},
            {'cond_type': 'pattern', 'operator': 'equals', 'value': 'set_port_2($ARG)'}
        ]
    }
    parser = SastCheckParser()
    parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
    assert parsed_check == {
        'id': 'CKV_SAST_1', 'message': 'some guidelines', 'severity': 'INFO', 'languages': ['python'], 'metadata': {
            'name': 'check name'},
        'patterns': [
            {'pattern': 'set_port_1($ARG)'},
            {'pattern': 'set_port_2($ARG)'}
        ]
    }


def test_pattern_regex_parsing():
    raw_check = {
        'metadata': {'id': 'CKV_SAST_1', 'name': 'check name', 'guidelines': 'some guidelines', 'category': 'sast',
            'severity': 'LOW'}, 'scope': {'languages': ['python']},
        'definition': [
            {'cond_type': 'pattern', 'operator': 'equals', 'value': 'key = ...'},
            {'cond_type': 'pattern', 'operator': 'regex_match', 'value': '^.*(RSA)/.*'}
        ]
    }
    parser = SastCheckParser()
    parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
    assert parsed_check == {
        'id': 'CKV_SAST_1', 'message': 'some guidelines', 'severity': 'INFO', 'languages': ['python'], 'metadata': {
            'name': 'check name'},
        'patterns': [
            {'pattern': 'key = ...'},
            {'pattern-regex': '^.*(RSA)/.*'},
        ]
    }


def test_pattern_not_regex_parsing():
    raw_check = {
        'metadata': {'id': 'CKV_SAST_1', 'name': 'check name', 'guidelines': 'some guidelines', 'category': 'sast',
            'severity': 'LOW'}, 'scope': {'languages': ['python']},
        'definition': [
            {'cond_type': 'pattern', 'operator': 'equals', 'value': 'key = ...'},
            {'cond_type': 'pattern', 'operator': 'not_regex_match', 'value': '^.*(RSA)/.*'}
        ]
    }
    parser = SastCheckParser()
    parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
    assert parsed_check == {
        'id': 'CKV_SAST_1', 'message': 'some guidelines', 'severity': 'INFO', 'languages': ['python'], 'metadata': {
            'name': 'check name'},
        'patterns': [
            {'pattern': 'key = ...'},
            {'pattern-not-regex': '^.*(RSA)/.*'},
        ]
    }


def test_pattern_inside_parsing():
    raw_check = {
        'metadata': {'id': 'CKV_SAST_1', 'name': 'check name', 'guidelines': 'some guidelines', 'category': 'sast',
            'severity': 'LOW'}, 'scope': {'languages': ['python']},
        'definition': [
            {'cond_type': 'pattern', 'operator': 'equals', 'value': 'key = ...'},
            {'cond_type': 'filter', 'attribute': 'pattern', 'operator': 'within', 'value': 'def $FUNC(...):\n  ...\n'},
        ]
    }
    parser = SastCheckParser()
    parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
    assert parsed_check == {
        'id': 'CKV_SAST_1', 'message': 'some guidelines', 'severity': 'INFO', 'languages': ['python'], 'metadata': {
            'name': 'check name'},
        'patterns': [
            {'pattern': 'key = ...'},
            {'pattern-inside': 'def $FUNC(...):\n  ...\n'},
        ]
    }


def test_pattern_not_inside_parsing():
    raw_check = {
        'metadata': {'id': 'CKV_SAST_1', 'name': 'check name', 'guidelines': 'some guidelines', 'category': 'sast',
            'severity': 'LOW'}, 'scope': {'languages': ['python']},
        'definition': [
            {'cond_type': 'pattern', 'operator': 'equals', 'value': 'key = ...'},
            {'cond_type': 'filter', 'attribute': 'pattern', 'operator': 'not_within', 'value': 'def $FUNC(...):\n  ...\n'},
        ]
    }
    parser = SastCheckParser()
    parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
    assert parsed_check == {
        'id': 'CKV_SAST_1', 'message': 'some guidelines', 'severity': 'INFO', 'languages': ['python'], 'metadata': {
            'name': 'check name'},
        'patterns': [
            {'pattern': 'key = ...'},
            {'pattern-not-inside': 'def $FUNC(...):\n  ...\n'},
        ]
    }


def test_metavariable_pattern_parsing():
    raw_check = {
        'metadata': {'id': 'CKV_SAST_1', 'name': 'check name', 'guidelines': 'some guidelines', 'category': 'sast',
            'severity': 'LOW'}, 'scope': {'languages': ['python']},
        'definition': [
            {'cond_type': 'pattern', 'operator': 'equals', 'value': 'key = $KEY'},
            {'cond_type': 'variable', 'variable': '$KEY', 'operator': 'pattern_match', 'value': '...'},
        ]
    }
    parser = SastCheckParser()
    parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
    print (parsed_check)
    assert parsed_check == {
        'id': 'CKV_SAST_1', 'message': 'some guidelines', 'severity': 'INFO', 'languages': ['python'], 'metadata': {
            'name': 'check name'},
        'patterns': [
            {'pattern': 'key = $KEY'},
            {'metavariable-pattern': {
                'metavariable': '$KEY',
                'pattern': '...'
                }
            },
        ]
    }


def test_metavariable_regex_parsing():
    raw_check = {
        'metadata': {'id': 'CKV_SAST_1', 'name': 'check name', 'guidelines': 'some guidelines', 'category': 'sast',
            'severity': 'LOW'}, 'scope': {'languages': ['python']},
        'definition': [
            {'cond_type': 'pattern', 'operator': 'equals', 'value': 'key = $KEY'},
            {'cond_type': 'variable', 'variable': '$KEY', 'operator': 'regex_match', 'value': '^.*(RSA)/.*'},
        ]
    }
    parser = SastCheckParser()
    parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
    print (parsed_check)
    assert parsed_check == {
        'id': 'CKV_SAST_1', 'message': 'some guidelines', 'severity': 'INFO', 'languages': ['python'], 'metadata': {
            'name': 'check name'},
        'patterns': [
            {'pattern': 'key = $KEY'},
            {'metavariable-regex': {
                'metavariable': '$KEY',
                'regex': '^.*(RSA)/.*'
                }
            },
        ]
    }


def test_metavariable_less_than_comparison_parsing():
    raw_check = {
        'metadata': {'id': 'CKV_SAST_1', 'name': 'check name', 'guidelines': 'some guidelines', 'category': 'sast',
            'severity': 'LOW'}, 'scope': {'languages': ['python']},
        'definition': [
            {'cond_type': 'pattern', 'operator': 'equals', 'value': 'key = $KEY'},
            {'cond_type': 'variable', 'variable': '$KEY', 'operator': 'less_than', 'value': '1024'},
        ]
    }
    parser = SastCheckParser()
    parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
    print (parsed_check)
    assert parsed_check == {
        'id': 'CKV_SAST_1', 'message': 'some guidelines', 'severity': 'INFO', 'languages': ['python'], 'metadata': {
            'name': 'check name'},
        'patterns': [
            {'pattern': 'key = $KEY'},
            {'metavariable-comparison': {
                'metavariable': '$KEY',
                'comparison': '$KEY < 1024'
                }
            },
        ]
    }


def test_metavariable_greater_than_comparison_parsing():
    raw_check = {
        'metadata': {'id': 'CKV_SAST_1', 'name': 'check name', 'guidelines': 'some guidelines', 'category': 'sast',
            'severity': 'LOW'}, 'scope': {'languages': ['python']},
        'definition': [
            {'cond_type': 'pattern', 'operator': 'equals', 'value': 'key = $KEY'},
            {'cond_type': 'variable', 'variable': '$KEY', 'operator': 'greater_than', 'value': '1024'},
        ]
    }
    parser = SastCheckParser()
    parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
    print (parsed_check)
    assert parsed_check == {
        'id': 'CKV_SAST_1', 'message': 'some guidelines', 'severity': 'INFO', 'languages': ['python'], 'metadata': {
            'name': 'check name'},
        'patterns': [
            {'pattern': 'key = $KEY'},
            {'metavariable-comparison': {
                'metavariable': '$KEY',
                'comparison': '$KEY > 1024'
                }
            },
        ]
    }

def test_basic_taint_mode_parsing():
    raw_check = {
        'mode': 'taint',
        'metadata': {'id': 'CKV_SAST_1', 'name': 'check name', 'guidelines': 'some guidelines', 'category': 'sast',
            'severity': 'LOW'}, 'scope': {'languages': ['python']},
        'definition': [
            {'cond_type': 'pattern_source', 'operator': 'equals', 'value': 'get_user_input(...)'},
            {'cond_type': 'pattern_sink', 'operator': 'equals', 'value': 'html_output(...)'},
        ]
    }
    parser = SastCheckParser()
    parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
    print (parsed_check)
    assert parsed_check == {
        'id': 'CKV_SAST_1', 'mode': 'taint', 'message': 'some guidelines', 'severity': 'INFO', 'languages': ['python'],
        'metadata': {'name': 'check name'},
        'pattern-sources': [{'pattern': 'get_user_input(...)'}],
        'pattern-sinks': [{'pattern': 'html_output(...)'}]
    }

def test_taint_mode_sanitizer_parsing():
    raw_check = {
        'mode': 'taint',
        'metadata': {'id': 'CKV_SAST_1', 'name': 'check name', 'guidelines': 'some guidelines', 'category': 'sast',
            'severity': 'LOW'}, 'scope': {'languages': ['python']},
        'definition': [
            {'cond_type': 'pattern_source', 'operator': 'equals', 'value': 'get_user_input(...)'},
            {'cond_type': 'pattern_sink', 'operator': 'equals', 'value': 'html_output(...)'},
            {'cond_type': 'pattern_sanitizer', 'operator': 'equals', 'value': 'sanitize(...)'}
        ]
    }
    parser = SastCheckParser()
    parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
    print (parsed_check)
    assert parsed_check == {
        'id': 'CKV_SAST_1', 'mode': 'taint', 'message': 'some guidelines', 'severity': 'INFO', 'languages': ['python'],
        'metadata': {'name': 'check name'},
        'pattern-sources': [{'pattern': 'get_user_input(...)'}],
        'pattern-sinks': [{'pattern': 'html_output(...)'}],
        'pattern-sanitizers': [{'pattern': 'sanitize(...)'}],
    }

def test_complex_taint_mode_parsing():
    raw_check = {
        'mode': 'taint',
        'metadata': {'id': 'CKV_SAST_1', 'name': 'check name', 'guidelines': 'some guidelines', 'category': 'sast',
            'severity': 'LOW'}, 'scope': {'languages': ['python']},
        'definition': [
            {'cond_type': 'pattern_source', 'operator': 'equals', 'value': {
                'and': [
                    {'cond_type': 'pattern', 'operator': 'equals', 'value': 'get_user_input(...)'},
                    {'cond_type': 'filter', 'attribute': 'pattern', 'operator': 'within', 'value': 'import pytest\n...\n'},
                ]
            }},
            {'cond_type': 'pattern_sink', 'operator': 'equals', 'value': 'html_output(...)'},
            {'cond_type': 'pattern_sanitizer', 'operator': 'equals', 'value': 'sanitize(...)'}
        ]
    }
    parser = SastCheckParser()
    parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
    print (parsed_check)
    assert parsed_check == {
        'id': 'CKV_SAST_1', 'mode': 'taint', 'message': 'some guidelines', 'severity': 'INFO', 'languages': ['python'],
        'metadata': {'name': 'check name'},
        'pattern-sources': [
            {'patterns': [
                {'pattern': 'get_user_input(...)'},
                {'pattern-inside': 'import pytest\n...\n'}
            ]
             }
        ],
        'pattern-sinks': [{'pattern': 'html_output(...)'}],
        'pattern-sanitizers': [{'pattern': 'sanitize(...)'}],
    }


def test_complex_policy_parsing():
    raw_check = {
        'metadata': {'id': 'CKV_SAST_1', 'name': 'check name', 'guidelines': 'some guidelines', 'category': 'sast',
            'severity': 'LOW'}, 'scope': {'languages': ['python']},
        'definition': [
            {'cond_type': 'pattern', 'operator': 'equals', 'value': 'set_port($ARG)'},
            {'cond_type': 'variable', 'variable': '$ARG', 'operator': 'less_than', 'value': 1024},
            {'or': [
                {'and': [
                    {'cond_type': 'pattern', 'operator': 'equals', 'value': 'func_2(...)'},
                    {'cond_type': 'pattern', 'operator': 'not_equals', 'value': 'func_2("...")'},
                    {'cond_type': 'filter', 'attribute': 'pattern', 'operator': 'within', 'value': 'import $PACKAGE\n...\n'}
                ]},
                {'cond_type': 'pattern', 'operator': 'equals', 'value': 'func_1(...)'}
            ]}
        ]
    }
    parser = SastCheckParser()
    parsed_check = parser.parse_raw_check_to_semgrep(raw_check)
    print (parsed_check)
    assert parsed_check == {
        'id': 'CKV_SAST_1', 'message': 'some guidelines', 'severity': 'INFO', 'languages': ['python'], 'metadata': {
            'name': 'check name'},
        'patterns': [
            {'pattern': 'set_port($ARG)'},
            {'metavariable-comparison': {
                'metavariable': '$ARG',
                'comparison': '$ARG < 1024'
            }},
            {'pattern-either': [
                {'patterns': [
                    {'pattern': 'func_2(...)'},
                    {'pattern-not': 'func_2("...")'},
                    {'pattern-inside': 'import $PACKAGE\n...\n'}
                ]},
                {'pattern': 'func_1(...)'}]
            }
        ]
    }
