# Deliberately dirty Python file used to exercise the analyzer.

import os

password = "hunter2"

# TODO: remove this debugging helper
def handle(user_code):
    eval(user_code)
    os.system("cleanup.sh")
