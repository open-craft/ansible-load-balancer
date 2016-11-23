default: test_prospector test_unit

test: test_prospector test_unit test_integration

venv-unit-tests: unit_test_requirements.txt
	virtualenv -p "`which python3`" "$@"
	"$@"/bin/pip install -r "$<"
	touch "$@"

venv-integration-tests: integration_test_requirements.txt
	virtualenv "$@"
	"$@"/bin/pip install -r "$<"
	touch "$@"

test_prospector: venv-unit-tests
	venv-unit-tests/bin/prospector \
	    --strictness veryhigh \
	    --test-warnings \
	    --member-warnings \
	    --full-pep8 \
	    --max-line-length=120 \
	    ../templates/manage_certs.py test_manage_certs.py

test_unit: venv-unit-tests
	PYTHONPATH=../templates venv-unit-tests/bin/coverage run \
	    --branch --source=../templates -m unittest test_manage_certs.py
	venv-unit-tests/bin/coverage html
	venv-unit-tests/bin/coverage report

test_integration: venv-integration-tests
	@if [ -z "$(TEST_DOMAIN)" ]; then \
	    echo "Please set TEST_DOMAIN to the domain name of the test server:"; \
	    echo "    make $@ TEST_DOMAIN=test.server.domain"; \
	    false; \
	fi
	venv-integration-tests/bin/ansible-playbook -vvv -i "$(TEST_DOMAIN)", integration.yml

clean:
	git clean -Xdf

.PHONY: default test test_prospector test_unit test_integration clean
