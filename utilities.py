import argparse
import csv
import pickle
import re
import sys
import time
from urllib.parse import unquote_plus

import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn import tree, linear_model
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split

# Feature order must match the training data columns
FEATURES = ['length', 'param_number', 'return_code', 'size',
            'upper_cases', 'lower_cases', 'special_chars', 'depth']
SPECIAL_CHARS = "[$&+,:;=?@#|'<>.^*()%!-]"

_LOG_REGEX = re.compile(
    r'([(\d\.)]+) - - \[(.*?)\] "(.*?)" (\d+) (.+) "(.*?)" "(.*?)"'
)


def encode_single_log_line(log_line: str) -> tuple[str, dict | None, str]:
    """Parse one Apache log line and return (url, feature_dict, return_code).

    Returns (url, None, return_code) when the line cannot be used for prediction.
    Returns ('', None, '') when the line does not match the expected format.
    """
    log_line = log_line.replace(',', '_')
    match = _LOG_REGEX.match(log_line)
    if match is None:
        return '', None, ''

    groups = match.groups()
    url = groups[2]
    return_code = groups[3]

    if url == '-':
        return url, None, return_code

    param_number = len(url.split('&'))
    url_length = len(url)
    size_str = str(groups[4]).rstrip('\n')
    depth = url.count('/')
    upper_cases = sum(1 for c in url if c.isupper())
    lower_cases = sum(1 for c in url if c.islower())
    special_chars = sum(1 for c in url if c in SPECIAL_CHARS)

    size = 0 if '-' in size_str else int(size_str)

    if int(return_code) <= 0:
        return url, None, return_code

    log_line_data: dict = {
        'size': size,
        'param_number': int(param_number),
        'length': int(url_length),
        'return_code': int(return_code),
        'upper_cases': int(upper_cases),
        'lower_cases': int(lower_cases),
        'special_chars': int(special_chars),
        'depth': int(depth),
    }
    return url, log_line_data, return_code


def load_model(model_file: str):
    """Load a pickled scikit-learn model from disk."""
    with open(model_file, 'rb') as f:
        return pickle.load(f)
