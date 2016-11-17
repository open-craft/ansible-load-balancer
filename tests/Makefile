all: lint unit_tests

lint:
	pylint3 --disable=I --reports=n ../templates/manage_certs.py
	PYTHONPATH=../templates pylint3 --max-line-length=120 --disable=missing-docstring --reports=n test_manage_certs.py

venv-unit-tests: unit_test_requirements.txt
	virtualenv -p "`which python3`" "$@"
	"$@"/bin/pip install -r "$<"

venv-integration-tests: integration_test_requirements.txt
	virtualenv "$@"
	"$@"/bin/pip install -r "$<"

unit_tests: venv-unit-tests
	PYTHONPATH=../templates venv-unit-tests/bin/python -m unittest test_manage_certs.py

integration_tests: venv-integration-tests
	@if [ -z "$(TEST_DOMAIN)" ]; then \
	    echo "Please set TEST_DOMAIN to the domain name of the test server:"; \
	    echo "    make $@ TEST_DOMAIN=test.server.domain"; \
	    false; \
	fi; \
	venv-integration-tests/bin/ansible-playbook -vvv -i "$(TEST_DOMAIN)", integration.yml

clean:
	rm -rf venv-unit-tests venv-integration-tests *.retry __pycache__

.PHONY: all lint unit_tests integration_tests clean
